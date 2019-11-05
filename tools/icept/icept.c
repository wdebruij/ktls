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
#include <fcntl.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "icept_tls.h"

static socklen_t cfg_addr_len;
static struct sockaddr *cfg_addr_dst;
static struct sockaddr *cfg_addr_listen;
static bool cfg_do_ktls_active;
static bool cfg_do_ktls_passive;
static const char *cfg_cgroup_path;
static int cfg_mark;
static const char *cfg_role;
static void (*cfg_role_fn)(void);
static bool cfg_sockmap;

static struct sockaddr_in cfg_addr4_dst = { .sin_family = AF_INET };
static struct sockaddr_in6 cfg_addr6_dst = { .sin6_family = AF_INET6 };

static struct sockaddr_in cfg_addr4_listen = { .sin_family = AF_INET,
					       .sin_addr.s_addr = INADDR_ANY };
static struct sockaddr_in6 cfg_addr6_listen = { .sin6_family = AF_INET6,
						.sin6_addr = IN6ADDR_ANY_INIT };

int map_fd;
struct bpf_object *obj;

static int open_active(bool do_mark)
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

	if (do_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK,
			       &cfg_mark, sizeof(cfg_mark)))
			error(1, errno, "setsockopt mark");
	}

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

	fd = open_active(false);

	/* TODO: avoid the need for this */
	usleep(100 * 1000);

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

static void do_intercept_getdstaddr(int fd)
{
	int level;

	if (cfg_addr_listen->sa_family == PF_INET)
		level = SOL_IP;
	else
		level = SOL_IPV6;

	if (getsockopt(fd, level, SO_ORIGINAL_DST,
		       cfg_addr_dst, &cfg_addr_len))
		error(1, errno, "getsockopt original dst");
}

static void bpf_check_ptr(const void *obj, const char *name)
{
	char err_buf[256];
	long err;

	if (!obj)
		error(1, 0, "bpf: %s: NULL ptr\n", name);

	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, err_buf, sizeof(err_buf));
		error(1, 0, "bpf: %s: %s\n", name, err_buf);
	}
}

static struct bpf_program *do_bpf_get_prog(const char *name,
					   enum bpf_prog_type type)
{
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_title(obj, name);
	bpf_check_ptr(obj, name);
	bpf_program__set_type(prog, type);

	return prog;
}

static void do_bpf_attach_prog(struct bpf_program *prog, int fd,
			       enum bpf_attach_type type)
{
	int prog_fd, ret;

	prog_fd = bpf_program__fd(prog);
	ret = bpf_prog_attach(prog_fd, fd, type, 0);
	if (ret)
		error(1, ret, "bpf attach prog %d", type);
	if (close(prog_fd))
		error(1, errno, "bpf close prog %d", type);
}

static void do_bpf_setup(void)
{
	struct bpf_program *prog_parse, *prog_verdict, *prog_cgroup, *prog_skmsg;
	struct bpf_map *map;

	obj = bpf_object__open("icept_bpf.o");
	bpf_check_ptr(obj, "obj");

	prog_parse = do_bpf_get_prog("prog_parser", BPF_PROG_TYPE_SK_SKB);
	prog_verdict = do_bpf_get_prog("prog_verdict", BPF_PROG_TYPE_SK_SKB);
	prog_cgroup = do_bpf_get_prog("prog_cgroup_sockops", BPF_PROG_TYPE_SOCK_OPS);
	prog_skmsg = do_bpf_get_prog("prog_skmsg", BPF_PROG_TYPE_SK_MSG);

	if (bpf_object__load(obj))
		error(1, 0, "bpf object load: %ld", libbpf_get_error(obj));

	map = bpf_object__find_map_by_name(obj, "sock_map");
	bpf_check_ptr(map, "map");
	map_fd = bpf_map__fd(map);

	do_bpf_attach_prog(prog_parse, map_fd, BPF_SK_SKB_STREAM_PARSER);
	do_bpf_attach_prog(prog_verdict, map_fd, BPF_SK_SKB_STREAM_VERDICT);

	if (cfg_cgroup_path) {
		int map_tx_fd, cgroup_fd;

		cgroup_fd = open(cfg_cgroup_path, O_DIRECTORY, O_RDONLY);
		if (cgroup_fd == -1)
			error(1, errno, "open cgroup");

		do_bpf_attach_prog(prog_cgroup, cgroup_fd, BPF_CGROUP_SOCK_OPS);

		if (close(cgroup_fd))
			error(1, errno, "close cgroup");

		map = bpf_object__find_map_by_name(obj, "sock_map_tx");
		bpf_check_ptr(map, "map_tx");
		map_tx_fd = bpf_map__fd(map);

		do_bpf_attach_prog(prog_skmsg, map_tx_fd, BPF_SK_MSG_VERDICT);
	}
}

static void do_bpf_cleanup(void)
{
	if (close(map_fd))
		error(1, errno, "close sockmap");

	bpf_object__close(obj);
}

static void do_intercept_sockmap(int fd, int conn_fd)
{
	struct tcp_info tcpi;
	socklen_t tcpi_len;
	struct pollfd pfd;
	uint32_t key, val;
	int ret;

	key = 0;
	val = fd;
	ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
	if (ret)
		error(1, ret, "bpf sockmap insert passive");

	key = 1;
	val = conn_fd;
	ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
	if (ret)
		error(1, ret, "bpf sockmap insert active");

	pfd.fd = fd;
	pfd.events = POLLRDHUP;

	ret = poll(&pfd, 1, 1000);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		error(1, 0, "poll: timeout");

	tcpi_len = sizeof(tcpi);
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpi_len))
		error(1, errno, "getsockopt tcp info");
	if (tcpi_len != sizeof(tcpi))
		error(1, 0, "getsockopt tcp info: length");

	fprintf(stderr, "[intercept] sockmap segs in=%d/out=%d bytes in=%lld/out=%lld\n",
			tcpi.tcpi_data_segs_in, tcpi.tcpi_data_segs_out,
			tcpi.tcpi_bytes_acked,
			tcpi.tcpi_bytes_sent - tcpi.tcpi_bytes_retrans);
}

static void do_intercept(void)
{
	SSL_CTX *ctx = NULL;
	int fd, conn_fd;
	SSL *ssl;
	char msg;

	if (cfg_do_ktls_passive || cfg_do_ktls_active) {
		ctx = setup_tls("test.pem");
		ssl = SSL_new(ctx);
		if (!ssl)
			error_ssl();
	}

	if (cfg_sockmap)
		do_bpf_setup();


	fd = open_passive();
	if (cfg_do_ktls_passive) {
		if (SSL_set_fd(ssl, fd) != 1)
			error_ssl();
		if (SSL_accept(ssl) != 1)
			error_ssl();
	}

	do_intercept_getdstaddr(fd);
	conn_fd = open_active(true);
	if (cfg_do_ktls_active) {
		if (SSL_set_fd(ssl, fd) != 1)
			error_ssl();
		if (SSL_connect(ssl) != 1)
			error_ssl();
	}

	if (cfg_sockmap) {
		do_intercept_sockmap(fd, conn_fd);
	} else {
		msg = read_msg(fd);
		write_msg(conn_fd, msg + 1);

		msg = read_msg(conn_fd);
		write_msg(fd, msg + 1);
	}

	if (close(conn_fd))
		error(1, errno, "[intercept] close active");
	if (close(fd))
		error(1, errno, "[intercept] close passive");

	if (cfg_sockmap)
		do_bpf_cleanup();

	if (ssl) {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}
}

static void __attribute__((noreturn)) usage(const char *filepath)
{
	error(1, 0, "Usage: %s [-46s] [-C cgroup_path ] [-d addr] [-D port] [-L port] [-m mark] <client|server|intercept>",
		    filepath);

	/* suppress compiler warning */
	exit(1);
}

static void parse_opts(int argc, char **argv)
{
	unsigned long port_dst = 0, port_listen = 0;
	const char *addr_dst = NULL;
	int c;

	while ((c = getopt(argc, argv, "46C:d:D:kKL:m:s")) != -1) {
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
		case 'C':
			cfg_cgroup_path = optarg;
			break;
		case 'd':
			addr_dst = optarg;
			break;
		case 'D':
			port_dst = strtol(optarg, NULL, 0);
			if (port_dst > USHRT_MAX)
				error(1, 0, "Parse error at dest port");
			break;
		case 'k':
			cfg_do_ktls_active = true;
			break;
		case 'K':
			cfg_do_ktls_passive = true;
			break;
		case 'L':
			port_listen = strtol(optarg, NULL, 0);
			if (port_listen > USHRT_MAX)
				error(1, 0, "Parse error at listen port");
			break;
		case 'm':
			cfg_mark = strtol(optarg, NULL, 0);
			if (cfg_mark > UINT32_MAX)
				error(1, 0, "Parse error at mark");
			break;
		case 's':
			cfg_sockmap = true;
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
	} else if (!strcmp(cfg_role, "intercept")) {
		if (!port_listen)
			usage(argv[0]);
		cfg_role_fn = do_intercept;
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

	if (cfg_role_fn != do_intercept &&
	    (cfg_do_ktls_active || cfg_do_ktls_passive))
		error(1, 0, "kTLS only supported between icept processes");
	if (cfg_do_ktls_active && cfg_do_ktls_passive)
		error(1, 0, "kTLS only used between icept, so one FD only");
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

