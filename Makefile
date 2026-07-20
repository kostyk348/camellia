# Camellia cipher library - Makefile
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -Iinclude
AR      ?= ar
PREFIX  ?= /usr/local

LIB     = libcamellia.a
SHLIB   = libcamellia.so

.PHONY: all lib shared static cli bench python test clean install

all: static shared cli bench test

static: $(LIB)
shared: $(SHLIB)

src/camellia.o: src/camellia.c include/camellia.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): src/camellia.o
	$(AR) rcs $@ $^

$(SHLIB): src/camellia.c include/camellia.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

test: tests/test_camellia
	./tests/test_camellia

tests/test_camellia: tests/test_camellia.c $(LIB) include/camellia.h
	$(CC) $(CFLAGS) -Iinclude $< $(LIB) -o $@

cli: camellia-cli
camellia-cli: tools/camellia-cli.c $(LIB) include/camellia.h
	$(CC) $(CFLAGS) -Iinclude $< $(LIB) -o $@

bench: tools/bench.c $(LIB) include/camellia.h
	@if pkg-config --exists openssl; then \
		$(CC) $(CFLAGS) -Iinclude -DHAVE_OPENSSL $< $(LIB) $(shell pkg-config --libs openssl) -o $@ ; \
	else \
		$(CC) $(CFLAGS) -Iinclude $< $(LIB) -o $@ ; \
	fi

python: $(SHLIB)
	cp $(SHLIB) python/

clean:
	rm -f src/camellia.o $(LIB) $(SHLIB) tests/test_camellia camellia-cli tools/bench
	rm -f python/$(SHLIB)

install: static shared
	install -d $(PREFIX)/lib $(PREFIX)/include
	install -m 644 $(LIB) $(SHLIB) $(PREFIX)/lib/
	install -m 644 include/camellia.h $(PREFIX)/include/
