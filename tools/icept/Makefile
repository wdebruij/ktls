
.PHONY: all clean distclean

all: icept

icept: icept.o
	gcc -static $+ -o $@

%.o: %.c
	gcc -c -Wall -Werror $< -o $@

clean:
	-rm -f *.o

distclean: clean
	-rm -f icept
