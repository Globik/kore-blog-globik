/*
 * Copyright (c) 2018 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <kore/kore.h>
#include <kore/http.h>

#include <sodium.h>

#include <ctype.h>
#include <fts.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "assets.h"

#define BLOG_SESSION_LEN	32

#define MSG_SESSION_ADD		100
#define MSG_SESSION_DEL		200

#define BLOG_DIR		"blogs"
#define BLOG_VER		"kore-blog v0.1"
#define BLOG_USER_CONF		"users.conf"

#define POST_FLAG_DRAFT		0x0001

struct cache {
	u_int32_t		refs;
	struct kore_buf		buf;
};

struct session {
	uint32_t		uid;
	char			data[(BLOG_SESSION_LEN * 2) + 1];
};

struct user {
	u_int32_t		uid;
	char			*name;
	struct session		session;
	char			*passphrase;
	TAILQ_ENTRY(user)	list;
};

struct post {
	int			flags;
	size_t			coff;
	size_t			clen;
	time_t			mtime;
	char			*uri;
	char			*file;
	char			*title;
	struct cache		*cache;
	TAILQ_ENTRY(post)	list;
};

void	user_reload(void);
void	index_rebuild(void);
void	signal_handler(int);
void	tick(void *, u_int64_t);
int	cache_sent(struct netbuf *);
int	fts_compare(const FTSENT **, const FTSENT **);

struct cache	*cache_create(size_t);
struct post	*post_register(char *);
void		post_cache(struct post *);
void		post_remove(struct post *);
int		post_send(struct http_request *, const char *, int);
void		cache_ref_drop(struct cache **);

int	auth_login(struct http_request *);
int	auth_user_exists(struct http_request *, char *);
void	auth_session_add(struct kore_msg *, const void *);
void	auth_session_del(struct kore_msg *, const void *);
int	auth_session(struct http_request *, const char *);

int	redirect(struct http_request *);
int	post_list(struct http_request *);
int	post_render(struct http_request *);
int	draft_list(struct http_request *);
int	draft_render(struct http_request *);
int	referer(struct http_request *, const void *);
int	list_posts(struct http_request *, const char *, struct cache **, int);

static TAILQ_HEAD(, post)	posts;
static TAILQ_HEAD(, user)	users;
static volatile sig_atomic_t	blog_sig = -1;
static time_t			user_mtime = 0;

static struct cache		*live_index = NULL;
static struct cache		*draft_index = NULL;

void
signal_handler(int sig)
{
	blog_sig = sig;
}

void
tick(void *unused, u_int64_t now)
{
	if (blog_sig == SIGHUP) {
		blog_sig = -1;
		index_rebuild();
		user_reload();
	}
}

void
kore_worker_configure(void)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);

	(void)kore_timer_add(tick, 1000, NULL, 0);

	TAILQ_INIT(&posts);
	TAILQ_INIT(&users);

	index_rebuild();
	user_reload();

	kore_msg_register(MSG_SESSION_ADD, auth_session_add);
	kore_msg_register(MSG_SESSION_DEL, auth_session_del);
}

struct cache *
cache_create(size_t len)
{
	struct cache		*cache;

	cache = kore_calloc(1, sizeof(*cache));

	cache->refs++;
	kore_buf_init(&cache->buf, len);

	return (cache);
}

void
cache_ref_drop(struct cache **ptr)
{
	struct cache	*cache = *ptr;

	cache->refs--;

	if (cache->refs == 0) {
		kore_buf_cleanup(&cache->buf);
		kore_free(cache);
		*ptr = NULL;
	}
}

int
cache_sent(struct netbuf *nb)
{
	struct cache	*cache = (struct cache *)nb->extra;

	cache_ref_drop(&cache);

	return (KORE_RESULT_OK);
}

int
fts_compare(const FTSENT **a, const FTSENT **b)
{
	const FTSENT	*a1 = *a;
	const FTSENT	*b1 = *b;

	if (a1->fts_statp->st_mtime > b1->fts_statp->st_mtime)
		return (-1);

	if (a1->fts_statp->st_mtime < b1->fts_statp->st_mtime)
		return (1);

	return (0);
}

void
user_reload(void)
{
	struct stat	st;
	FILE		*fp;
	u_int32_t	uids;
	struct user	*user;
	int		lineno;
	char		*line, *pwd, buf[256];

	if (stat(BLOG_USER_CONF, &st) == -1) {
		if (errno != ENOENT) {
			kore_log(LOG_INFO,
			    "stat(%s): %s", BLOG_USER_CONF, errno_s);
		}
		return;
	}

	if (user_mtime == st.st_mtime)
		return;

	while (!TAILQ_EMPTY(&users)) {
		user = TAILQ_FIRST(&users);
		TAILQ_REMOVE(&users, user, list);
		kore_free(user->passphrase);
		kore_free(user->name);
		kore_free(user);
	}

	TAILQ_INIT(&users);

	if ((fp = fopen(BLOG_USER_CONF, "r")) == NULL) {
		if (errno != ENOENT) {
			kore_log(LOG_INFO,
			    "fopen(%s): %s", BLOG_USER_CONF, errno_s);
		}
		return;
	}

	kore_log(LOG_INFO, "reloading users");

	uids = 1;
	lineno = 0;

	while ((line = kore_read_line(fp, buf, sizeof(buf))) != NULL) {
		lineno++;

		if (*line == '\0')
			continue;

		if ((pwd = strchr(line, ':')) == NULL) {
			kore_log(LOG_INFO, "malformed user @ %d", lineno);
			continue;
		}

		*(pwd)++ = '\0';

		if (*line == '\0' || *pwd == '\0') {
			kore_log(LOG_INFO, "malformed user @ %d", lineno);
			continue;
		}

		user = kore_calloc(1, sizeof(*user));
		user->uid = uids++;
		user->name = kore_strdup(line);
		user->passphrase = kore_strdup(pwd);
		TAILQ_INSERT_TAIL(&users, user, list);
	}

	fclose(fp);
	user_mtime = st.st_mtime;
}

void
index_rebuild(void)
{
	FTSENT		*fe;
	FTS		*fts;
	struct post	*post;
	char		*path[] = { BLOG_DIR, NULL };

	kore_log(LOG_INFO, "rebuilding post list");

	if (live_index != NULL)
		cache_ref_drop(&live_index);

	if (draft_index != NULL)
		cache_ref_drop(&draft_index);

	if ((fts = fts_open(path,
	    FTS_NOCHDIR | FTS_PHYSICAL, fts_compare)) == NULL) {
		kore_log(LOG_ERR, "fts_open(): %s", errno_s);
		return;
	}

	while (!TAILQ_EMPTY(&posts)) {
		post = TAILQ_FIRST(&posts);
		post_remove(post);
	}

	TAILQ_INIT(&posts);

	while ((fe = fts_read(fts)) != NULL) {
		if (!S_ISREG(fe->fts_statp->st_mode))
			continue;
		if ((post = post_register(fe->fts_accpath)) != NULL)
			post_cache(post);
	}

	fts_close(fts);
}

void
post_cache(struct post *post)
{
	int		fd;
	struct stat	st;
	ssize_t		bytes;
	u_int8_t	buf[4096];

	if ((fd = open(post->file, O_RDONLY)) == -1) {
		kore_log(LOG_ERR, "failed to open '%s' (%s)",
		    post->file, errno_s);
		post_remove(post);
		return;
	}

	if (fstat(fd, &st) == -1) {
		kore_log(LOG_ERR, "fstat(%s): %s", post->file, errno_s);
		post_remove(post);
		return;
	}

	post->mtime = st.st_mtime;
	post->cache = cache_create(st.st_size);

	kore_buf_appendf(&post->cache->buf,
	    (const char *)asset_post_start_html, post->title, post->title);

	post->clen = 0;
	post->coff = post->cache->buf.offset;

	for (;;) {
		bytes = read(fd, buf, sizeof(buf));
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			kore_log(LOG_ERR, "read(%s): %s", post->file, errno_s);
			post_remove(post);
			close(fd);
			return;
		}

		if (bytes == 0)
			break;

		post->clen += bytes;
		kore_buf_append(&post->cache->buf, buf, bytes);
	}

	close(fd);

	kore_buf_appendf(&post->cache->buf,
	    (const char *)asset_blog_version_html, BLOG_VER);

	kore_buf_append(&post->cache->buf, asset_post_end_html,
	    asset_len_post_end_html);
}

struct post *
post_register(char *path)
{
	struct post	*post;
	int		invalid;
	char		*p, *fpath, *uri, title[128];

	if (strlen(path) <= (strlen(BLOG_DIR) + 1))
		fatal("invalid path from fts_read()?");

	uri = path + strlen(BLOG_DIR) + 1;
	if (uri[0] == '.' || uri[0] == '\0')
		return (NULL);

	fpath = kore_strdup(path);
	if ((p = strrchr(path, '.')) != NULL)
		*p = '\0';

	if (kore_strlcpy(title, uri, sizeof(title)) >= sizeof(title)) {
		kore_free(fpath);
		kore_log(LOG_ERR, "blog name (title) '%s' too long", uri);
		return (NULL);
	}

	invalid = 0;
	for (p = &uri[0]; *p != '\0'; p++) {
		if (*p == ' ' || *p == '-' || *p == '_') {
			*p = '-';
			continue;
		}

		if (!isalnum(*(unsigned char *)p)) {
			invalid++;
			continue;
		}

		if (*p >= 'A' && *p <= 'Z')
			*p += 0x20;
	}

	if (invalid) {
		kore_free(fpath);
		kore_log(LOG_ERR, "'%s' contains invalid characters", fpath);
		return (NULL);
	}

	post = kore_calloc(1, sizeof(*post));
	post->flags = 0;
	post->file = fpath;
	post->uri = kore_strdup(uri);
	post->title = kore_strdup(title);
	TAILQ_INSERT_TAIL(&posts, post, list);

	if (strstr(post->file, "draft"))
		post->flags |= POST_FLAG_DRAFT;

	return (post);
}

void
post_remove(struct post *post)
{
	cache_ref_drop(&post->cache);

	TAILQ_REMOVE(&posts, post, list);
	kore_free(post->title);
	kore_free(post->file);
	kore_free(post->uri);
	kore_free(post);
}

int
referer(struct http_request *req, const void *unused)
{
	const char		*ref, *p;

	if (!http_request_header(req, "referer", &ref))
		return (KORE_RESULT_OK);

	p = ref;

	while (*p != '\0') {
		if (!isprint(*(const unsigned char *)p++)) {
			ref = "[not printable]";
			break;
		}
	}

	kore_log(LOG_NOTICE, "blog (%s) visit from %s", req->path, ref);

	return (KORE_RESULT_OK);
}

int
auth_login(struct http_request *req)
{
	size_t			i;
	int			len;
	struct user		*up;
	struct session		session;
	char			*user, *pass;
	u_int8_t		buf[BLOG_SESSION_LEN];

	if (req->method == HTTP_METHOD_GET)
		return (asset_serve_login_html(req));

	http_populate_post(req);

	if (!http_argument_get_string(req, "user", &user) ||
	    !http_argument_get_string(req, "passphrase", &pass)) {
		req->method = HTTP_METHOD_GET;
		return (asset_serve_login_html(req));
	}

	up = NULL;
	TAILQ_FOREACH(up, &users, list) {
		if (!strcmp(user, up->name))
			break;
	}

	if (up == NULL) {
		req->method = HTTP_METHOD_GET;
		kore_log(LOG_INFO, "auth_login: no user data?");
		return (asset_serve_login_html(req));
	}

	if (crypto_pwhash_str_verify(up->passphrase, pass, strlen(pass)) != 0) {
		req->method = HTTP_METHOD_GET;
		return (asset_serve_login_html(req));
	}

	session.uid = up->uid;
	memset(session.data, 0, sizeof(session.data));

	randombytes_buf(buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++) {
		len = snprintf(session.data + (i * 2),
		    sizeof(session.data) - (i * 2), "%02x", buf[i]);
		if (len == -1 || (size_t)len >= sizeof(session.data)) {
			kore_log(LOG_ERR, "failed to hexify session");
			req->method = HTTP_METHOD_GET;
			return (asset_serve_login_html(req));
		}
	}

	kore_msg_send(KORE_MSG_WORKER_ALL, MSG_SESSION_ADD,
	    &session, sizeof(session));

	http_response_header(req, "location", "/drafts/");
	http_response_cookie(req, "blog_token", session.data,
	    "/drafts/", 0, 0, NULL);

	kore_log(LOG_INFO, "login for '%s'", up->name);
	http_response(req, HTTP_STATUS_FOUND, NULL, 0);

	return (KORE_RESULT_OK);
}

int
auth_user_exists(struct http_request *req, char *user)
{
	struct user	*usr;

	if (user == NULL)
		return (KORE_RESULT_ERROR);

	TAILQ_FOREACH(usr, &users, list) {
		if (!strcmp(usr->name, user))
			return (KORE_RESULT_OK);
	}

	return (KORE_RESULT_ERROR);
}

void
auth_session_add(struct kore_msg *msg, const void *data)
{
	struct user		*user;
	const struct session	*session;

	if (msg->length != sizeof(*session)) {
		kore_log(LOG_ERR, "auth_session_add: invalid len (%u)",
		    msg->length);
		return;
	}

	session = data;

	TAILQ_FOREACH(user, &users, list) {
		if (user->uid == session->uid) {
			memcpy(&user->session, session, sizeof(*session));
			break;
		}
	}
}

void
auth_session_del(struct kore_msg *msg, const void *data)
{
	u_int32_t	uid;
	struct user	*user;

	if (msg->length != sizeof(uid)) {
		kore_log(LOG_ERR, "auth_session_del: invalid len (%u)",
		    msg->length);
		return;
	}

	memcpy(&uid, data, sizeof(uid));

	TAILQ_FOREACH(user, &users, list) {
		if (user->uid == uid) {
			memset(&user->session, 0, sizeof(user->session));
			break;
		}
	}
}

int
auth_session(struct http_request *req, const char *cookie)
{
	struct user	*user;

	if (cookie == NULL)
		return (KORE_RESULT_ERROR);

	TAILQ_FOREACH(user, &users, list) {
		if (!strcmp(user->session.data, cookie)) {
			kore_log(LOG_INFO, "%s requested by %s",
			    req->path, user->name);
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

int
redirect(struct http_request *req)
{
	http_response_header(req, "location", "/");
	http_response(req, HTTP_STATUS_FOUND, NULL, 0);
	return (KORE_RESULT_OK);
}

int
post_list(struct http_request *req)
{
	return (list_posts(req, "posts", &live_index, 0));
}

int
draft_list(struct http_request *req)
{
	return (list_posts(req, "drafts", &draft_index, POST_FLAG_DRAFT));
}

int
list_posts(struct http_request *req, const char *type, struct cache **ptr,
    int flags)
{
	struct post		*post;
	struct cache		*cache;

	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "get");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return (KORE_RESULT_OK);
	}

	cache = *ptr;

	if (cache == NULL) {
		cache = cache_create(4096);
		kore_buf_append(&cache->buf,
		    asset_index_top_html, asset_len_index_top_html);

		TAILQ_FOREACH(post, &posts, list) {
			if (post->flags != flags)
				continue;
			kore_buf_appendf(&cache->buf,
			    (const char *)asset_index_entry_html,
			    type, post->uri, post->title);
		}

		kore_buf_appendf(&cache->buf,
		    (const char *)asset_blog_version_html, BLOG_VER);
		kore_buf_append(&cache->buf,
		    asset_index_end_html, asset_len_index_end_html);

		*ptr = cache;
	}

	cache->refs++;

	http_response_header(req, "content-type", "text/html; charset=utf-8");
	http_response_stream(req, HTTP_STATUS_OK, cache->buf.data,
	    cache->buf.offset, cache_sent, cache);

	return (KORE_RESULT_OK);
}

int
draft_render(struct http_request *req)
{
	return (post_send(req, "/drafts/", POST_FLAG_DRAFT));
}

int
post_render(struct http_request *req)
{
	return (post_send(req, "/posts/", 0));
}

int
post_send(struct http_request *req, const char *path, int flags)
{
	const char	*uri;
	struct post	*post;
	int		redirect;

	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "get");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return (KORE_RESULT_OK);
	}

	if (strlen(req->path) <= strlen(path)) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (KORE_RESULT_OK);
	}

	post = NULL;
	redirect = 0;
	uri = req->path + strlen(path);

	TAILQ_FOREACH(post, &posts, list) {
		if (post->flags != flags)
			continue;
		if (!strcmp(post->uri, uri))
			break;
	}

	if (post == NULL) {
		redirect++;
	} else if (post->cache == NULL) {
		redirect++;
		kore_log(LOG_ERR, "no cache for %s", post->uri);
	}

	if (redirect) {
		http_response_header(req, "location", "/");
		http_response(req, HTTP_STATUS_FOUND, NULL, 0);
		return (KORE_RESULT_OK);
	}

	post->cache->refs++;

	http_response_header(req, "content-type", "text/html; charset=utf-8");
	http_response_stream(req, HTTP_STATUS_OK, post->cache->buf.data,
	    post->cache->buf.offset, cache_sent, post->cache);

	return (KORE_RESULT_OK);
}
