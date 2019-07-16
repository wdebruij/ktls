/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Test flow interception
 *
 * Implements a simple TCP client, server and interception service.
 * Intended to be called from icept.sh
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <limits.h>
#include <netinet/ip6.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static socklen_t cfg_addr_len;
static struct sockaddr *cfg_addr_dst;
static struct sockaddr *cfg_addr_listen;
static const char *cfg_role;
static void (*cfg_role_fn)(void);

static struct sockaddr_in cfg_addr4_dst = { .sin_family = AF_INET };
static struct sockaddr_in6 cfg_addr6_dst = { .sin6_family = AF_INET6 };

static struct sockaddr_in cfg_addr4_listen = { .sin_family = AF_INET,
					       .sin_addr.s_addr = INADDR_ANY };
static struct sockaddr_in6 cfg_addr6_listen = { .sin6_family = AF_INET6,
						.sin6_addr = IN6ADDR_ANY_INIT };

static int open_active(void)
{
	struct timeval tv;
	int fd;

	fd = socket(cfg_addr_dst->sa_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	tv.tv_sec = 0;
	tv.tv_usec = 300 * 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
		error(1, errno, "setsockopt sndtimeo");

	if (connect(fd, cfg_addr_dst, cfg_addr_len))
		error(1, errno, "[%s] connect (%d)", cfg_role, errno);

	return fd;
}

static int open_passive(void)
{
	int fd, conn_fd, one = 1;

	fd = socket(cfg_addr_listen->sa_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		error(1, errno, "setsockopt reuseaddr");

	if (bind(fd, cfg_addr_listen, cfg_addr_len))
		error(1, errno, "bind");

	if (listen(fd, 1))
		error(1, errno, "listen");

	conn_fd = accept(fd, NULL, NULL);
	if (conn_fd == -1)
		error(1, errno, "accept");
	if (close(fd))
		error(1, errno, "close");

	fprintf(stderr, "[%s] accepted\n", cfg_role);
	return conn_fd;
}

static void write_msg(int fd, char msg)
{
	int ret;

	fprintf(stderr, "[%s]  write: %c\n", cfg_role, msg);

	ret = write(fd, &msg, sizeof(msg));
	if (ret == -1)
		error(1, errno, "[%s] write", cfg_role);
	if (ret != sizeof(msg))
		error(1, 0, "[%s] write: length", cfg_role);
}

static char read_msg(int fd)
{
	char rbuf[2];
	int ret;

	ret = read(fd, rbuf, sizeof(rbuf));
	if (ret == -1)
		error(1, errno, "[%s] read", cfg_role);
	if (ret != 1)
		error(1, 0, "[%s] read: length", cfg_role);

	fprintf(stderr, "[%s]  read: %c\n", cfg_role, rbuf[0]);
	return rbuf[0];
}

static void do_client(void)
{
	int fd;

	fd = open_active();

	write_msg(fd, 'a');
	read_msg(fd);

	if (close(fd))
		error(1, errno, "[client] close active");
}

static void do_server(void)
{
	char msg;
	int fd;

	fd = open_passive();

	msg = read_msg(fd);
	write_msg(fd, msg + 1);

	if (close(fd))
		error(1, errno, "[server] close passive");
}

static void __attribute__((noreturn)) usage(const char *filepath)
{
	error(1, 0, "Usage: %s [-46] [-d addr] [-D port] [-L port] <client|server> \n",
		    filepath);

	/* suppress compiler warning */
	exit(1);
}

static void parse_opts(int argc, char **argv)
{
	unsigned long port_dst = 0, port_listen = 0;
	const char *addr_dst = NULL;
	int c;

	while ((c = getopt(argc, argv, "46d:D:L:")) != -1) {
		switch (c) {
		case '4':
			if (cfg_addr_dst)
				error(1, 0, "Pass one of -4 or -6");
			cfg_addr_len = sizeof(struct sockaddr_in);
			cfg_addr_dst = (struct sockaddr *)&cfg_addr4_dst;
			cfg_addr_listen = (struct sockaddr *)&cfg_addr4_listen;
			break;
		case '6':
			if (cfg_addr_dst)
				error(1, 0, "Pass one of -4 or -6");
			cfg_addr_len = sizeof(struct sockaddr_in6);
			cfg_addr_dst = (struct sockaddr *)&cfg_addr6_dst;
			cfg_addr_listen = (struct sockaddr *)&cfg_addr6_listen;
			break;
		case 'd':
			addr_dst = optarg;
			break;
		case 'D':
			port_dst = strtol(optarg, NULL, 0);
			if (port_dst > USHRT_MAX)
				error(1, 0, "Parse error at dest port");
			break;
		case 'L':
			port_listen = strtol(optarg, NULL, 0);
			if (port_listen > USHRT_MAX)
				error(1, 0, "Parse error at listen port");
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!cfg_addr_len)
		error(1, 0, "must specify address family");

	/* positional parameter: role */
	if (optind != argc - 1)
		usage(argv[0]);

	cfg_role = argv[optind];
	if (!strcmp(cfg_role, "client")) {
		if (!addr_dst || !port_dst)
			usage(argv[0]);
		cfg_role_fn = do_client;
	} else if (!strcmp(cfg_role, "server")) {
		if (!port_listen)
			usage(argv[0]);
		cfg_role_fn = do_server;
	} else {
		usage(argv[0]);
	}

	/* complete dest and listen sockaddr */
	if (cfg_addr_dst->sa_family == PF_INET) {
		if (addr_dst &&
		    inet_pton(AF_INET, addr_dst, &(cfg_addr4_dst.sin_addr)) != 1)
			error(1, 0, "ipv4 parse error: %s", addr_dst);
		cfg_addr4_dst.sin_port = htons(port_dst);
		cfg_addr4_listen.sin_port = htons(port_listen);
	} else {
		if (addr_dst &&
		    inet_pton(AF_INET6, addr_dst, &(cfg_addr6_dst.sin6_addr)) != 1)
			error(1, 0, "ipv6 parse error: %s", addr_dst);
		cfg_addr6_dst.sin6_port = htons(port_dst);
		cfg_addr6_listen.sin6_port = htons(port_listen);
	}
}

int main(int argc, char **argv)
{
	if (argc < 2)
		usage(argv[0]);

	parse_opts(argc, argv);

	fprintf(stderr, "[%s] up\n", cfg_role);
	cfg_role_fn();
	fprintf(stderr, "[%s] down\n", cfg_role);

	return 0;
}
