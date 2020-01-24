
.PHONY: all clean distclean test test_tls test_ktls test_tls_verbose test_ktls_verbose

all: ktls ktls_static ktls_boringssl cert.pem

ktls: ktls.o
	gcc $+ -o $@ -l:libssl.so.1.0.2 -l:libcrypto.so.1.0.2 -lpthread -ldl

ktls_static: ktls.o
	gcc $+ -static -o $@ -lssl -lcrypto -lz -ldl -static-libgcc

ktls_boringssl.o: ktls.c
	gcc $+ -o $@ -c -Iboringssl/include -Wall -Werror

ktls_boringssl: ktls_boringssl.o boringssl/build/ssl/libssl.a boringssl/build/crypto/libcrypto.a
	gcc -o $@ $+ -lz -lpthread -ldl

%.o: %.c
	gcc -ggdb -c -Wall -Werror $< -o $@

key.pem:
	openssl genrsa -out $@ 4096

cert.pem: key.pem
	openssl req -nodes -new -x509 \
		-subj "/CN=localhost/" \
		-key $< -out $@


# test pure openssl, no code of ours

test_tls_openssl_verbose:
	openssl s_server -accept 443 -cert cert.pem -key key.pem &
	sleep 0.4
	echo a | openssl s_client -connect localhost:443 -CAfile cert.pem


# test openssl build: tls, ktls, ktls + splice
#
# verbose modes use s_client to display negotiated cipher
# optionally add -debug for even more output

test_tls:
	./ktls &
	sleep 0.4
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cafile=cert.pem

test_ktls:
	./ktls -k &
	sleep 0.4
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cafile=cert.pem

test_ktls_verbose:
	./ktls -k &
	sleep 0.4
	echo a | openssl s_client -connect localhost:443 -CAfile cert.pem

test_ktls_splice:
	./ktls -k -s &
	sleep 0.4
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cafile=cert.pem


# test boringssl build: tls, ktls

test_tls_boringssl:
	./ktls_boringssl &
	sleep 0.4
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cafile=cert.pem

test_ktls_boringssl:
	./ktls_boringssl -k &
	sleep 0.4
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cafile=cert.pem

test_ktls_boringssl_verbose:
	./ktls_boringssl -k &
	sleep 0.4
	echo a | openssl s_client -tls1_2 -cipher AES128-GCM-SHA256 -connect localhost:443 -CAfile cert.pem


test: test_tls test_ktls

boringssl:
	echo "boringssl build requires cmake and golang"
	git clone https://boringssl.googlesource.com/boringssl

boringssl/build: boringssl
	mkdir -p boringssl/build

boringssl/build/Makefile: boringssl/build
	(cd boringssl/build && cmake ..)

boringssl/build/ssl/libssl.a: boringssl/build/Makefile
	(cd boringssl/build && make)

boringssl/build/cryto/libcrypto.a: boringssl/build/ssl/libssl.a

clean:
	-rm -f *.o *.pem
	-rm -rf boringssl

distclean: clean
	-rm -f ktls ktls_static ktls_boringssl
