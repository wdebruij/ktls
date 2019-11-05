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

#define _GNU_SOURCE

#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/tls.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#include "icept_tls.h"

/* define some openssl internals */
#ifndef EVP_AES_GCM_CTX
typedef struct { uint64_t val[2]; } uint128_t;

struct gcm128_context {
	uint128_t Yi,EKi,EK0,len,Xi,H;
	uint128_t Htable[16];
	void *gmult;
	void *ghash;
	unsigned int mres, ares;
	void *block;
	void *key;
};

typedef struct {
	union {
		double align;	/* essential, see with pahole */
		AES_KEY ks;
	} ks;
	int key_set;
	int iv_set;
	GCM128_CONTEXT gcm;
	unsigned char *iv;
	int ivlen;
	int taglen;
	int iv_gen;
	int tls_aad_len;
	ctr128_f ctr;
} EVP_AES_GCM_CTX;
#endif

void error_ssl(void)
{
	ERR_print_errors_fp(stderr);
	exit(1);
}

SSL_CTX * setup_tls(const char *pem_file)
{
	SSL_CTX *ctx;

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx)
		error_ssl();

	if (SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256") != 1)
		error_ssl();

	if (SSL_CTX_use_certificate_file(ctx, pem_file, SSL_FILETYPE_PEM) != 1)
		error_ssl();

	if (SSL_CTX_use_PrivateKey_file(ctx, pem_file, SSL_FILETYPE_PEM) != 1)
		error_ssl();

	return ctx;
}

static void __setup_kernel_tls(SSL *ssl, int fd, bool is_tx)
{
	struct tls12_crypto_info_aes_gcm_128 ci = {0};
	struct ssl_st *_ssl = (void *) ssl;
	EVP_AES_GCM_CTX *ctx;
	unsigned char *seq;
	int optname;

	if (is_tx) {
		ctx = (void *) _ssl->enc_write_ctx->cipher_data;
		seq = _ssl->s3->write_sequence;
		optname = TLS_TX;
	} else {
		ctx = (void *) _ssl->enc_read_ctx->cipher_data;
		seq = _ssl->s3->read_sequence;
		optname = TLS_RX;
	}

	ci.info.version = TLS_1_2_VERSION;
	ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	memcpy(ci.rec_seq, seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(ci.key, ctx->gcm.key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(ci.salt, ctx->iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(ci.iv, ctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);

	if (setsockopt(fd, SOL_TLS, optname, &ci, sizeof(ci)))
		error(1, errno, "setsockopt tls %cx", is_tx ? 't' : 'r');
}

void setup_kernel_tls(SSL *ssl, int fd)
{
	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")))
		error(1, errno, "setsockopt upper layer protocol");

	__setup_kernel_tls(ssl, fd, true);
	__setup_kernel_tls(ssl, fd, false);
}
