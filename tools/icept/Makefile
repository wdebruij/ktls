
.PHONY: all clean distclean

KSRC=../kernel
CLANG=clang-7
LLC=llc-7

all: icept icept_bpf.o

icept: icept.o
	gcc -static $+ -o $@ \
	    -L ${KSRC}/tools/lib/bpf -lbpf -lelf -lz

%_bpf.o: ../../third_party/icept/%_bpf.c
	$(CLANG) -I ${KSRC}/usr/include \
		 -I ${KSRC}/tools/testing/selftests/bpf \
		 -target bpf -O2 -emit-llvm -c $< -o - | \
		 $(LLC) -march=bpf -mcpu=generic -filetype=obj -o $@

%.o: %.c
	gcc  -I ${KSRC}/tools/lib -c -Wall -Werror $< -o $@

clean:
	-rm -f *.o

distclean: clean
	-rm -f icept
