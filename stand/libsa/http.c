/*
 * Copyright (c) 2019 Netflix, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Simple http implementation for libsa.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/in_systm.h>

#include <string.h>

#include "stand.h"
#include "net.h"
#include "netif.h"

static ssize_t recvhttp(struct iodesc *, void **, void **, time_t, void *);
static int http_open(const char *, struct open_file *);
static int http_close(struct open_file *);
static int http_read(struct open_file *, void *, size_t, size_t *);
static off_t http_seek(struct open_file *, off_t, int);
static int http_stat(struct open_file *, struct stat *);

struct fs_ops http_fsops = {
	.fs_name = "http",
	.fo_open = http_open,
	.fo_close = http_close,
	.fo_read = http_read,
	.fo_write = null_write,
	.fo_seek = http_seek,
	.fo_stat = http_stat,
	.fo_readdir = null_readdir
};

struct http_handle
{
	struct iodesc *iodesc;
	int				currblock;
	int				off;
	char			*path;
	void			*pkt;
};

extern struct in_addr servip;

static ssize_t
recvhttp(struct iodesc *d, void **pkt, void **payload, time_t tleft,
    void *recv_extra)
{
	return (0);
}



static int
http_open(const char *path, struct open_file *f)
{
	struct http_handle *httpfile;
	struct iodesc *io;
	int res;
	size_t pathsize;
	const char *extraslash;

	printf("http_open %s\n", path);


	httpfile = calloc(1, sizeof(*httpfile));
	if (httpfile == NULL)
		return (ENOMEM);

	httpfile->iodesc = io = socktodesc(*(int *)(f->f_devdata));
	if (io == NULL) {
		free(httpfile);
		return (EINVAL);
	}

	io->destip = servip;
	httpfile->off = 0;
	pathsize = (strlen(rootpath) + 1 + strlen(path) + 1) * sizeof(char);
	httpfile->path = malloc(pathsize);
	if (httpfile->path == NULL) {
		free(httpfile);
		return (ENOMEM);
	}
	if (rootpath[strlen(rootpath) - 1] == '/' || path[0] == '/')
		extraslash = "";
	else
		extraslash = "/";
	res = snprintf(httpfile->path, pathsize, "%s%s%s",
		rootpath, extraslash, path);
	if (res < 0 || res > pathsize) {
		free(httpfile->path);
		free(httpfile);
		return (ENOMEM);
	}

	netif_connect(io);

	f->f_fsdata = httpfile;

	printf("http path: %s\n", httpfile->path);
	return (0);
}

static int
http_read(struct open_file *f, void *addr, size_t size,
    size_t *resid /* out */)
{
	struct http_handle *httpfile = f->f_fsdata;
	printf("http_read: path=%s, size=%lu\n", httpfile->path, (unsigned long)size);

	if (httpfile->off == 0)
	{
		char req[1024];
		void *buffer = NULL;
		ssize_t ret;
		sprintf(req, "GET ");
		strcat(req, httpfile->path);
		strcat(req, " HTTP/1.1\r\n\r\n");

		// Send the request
		ret = netif_put(httpfile->iodesc, req, strlen(req) + 1);
		if (ret < 0) {
			printf("ERROR sending request: %zd\n", ret);
		} else if (ret < (strlen(req)+1)) {
			printf("SHORT write: %zd\n", ret);
		} else
		{
			ret = netif_get(httpfile->iodesc, &buffer, 1000);
			printf("GOT %zd bytes\n", ret);
		}
	}


	//sendrecv(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	return (0);
}

static int
http_close(struct open_file *f)
{
	return (0);
}

static int
http_stat(struct open_file *f, struct stat *sb)
{
	return (0);
}

static off_t
http_seek(struct open_file *f, off_t offset, int where)
{
	return (0);
}


