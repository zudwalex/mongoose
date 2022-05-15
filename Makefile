SRCS = mongoose.c test/unit_test.c test/packed_fs.c
HDRS = $(wildcard src/*.h)
DEFS ?= -DMG_MAX_HTTP_HEADERS=7 -DMG_ENABLE_LINES -DMG_ENABLE_PACKED_FS=1 -DMG_ENABLE_SSI=1
C_WARN ?= -Wmissing-prototypes -Wstrict-prototypes
WARN ?= -W -Wall -Werror -Wshadow -Wdouble-promotion -fno-common -Wconversion -Wundef $(C_WARN)
OPTS ?= -O3 -g3
VALGRIND_OPTS ?= -O0 -g3
INCS ?= -Isrc -I.
SSL ?= MBEDTLS
CWD ?= $(realpath $(CURDIR))
DOCKER ?= docker run --rm -e Tmp=. -e WINEDEBUG=-all -v $(CWD):$(CWD) -w $(CWD)
VCFLAGS = /nologo /W3 /O2 /I. $(DEFS) $(TFLAGS)
IPV6 ?= 1
ASAN ?= -fsanitize=address,undefined -fno-sanitize-recover=all
ASAN_OPTIONS ?= detect_leaks=1
EXAMPLES := $(wildcard examples/*)
PREFIX ?= /usr/local
VERSION ?= $(shell cut -d'"' -f2 src/version.h)
COMMON_CFLAGS ?= $(WARN) $(INCS) $(DEFS) -DMG_ENABLE_IPV6=$(IPV6) $(TFLAGS) $(EXTRA)
CFLAGS ?= $(OPTS) $(ASAN) $(COMMON_CFLAGS)
VALGRIND_CFLAGS ?= $(VALGRIND_OPTS) $(COMMON_CFLAGS)
VALGRIND_RUN ?= valgrind --tool=memcheck --gen-suppressions=all --leak-check=full --show-leak-kinds=all --leak-resolution=high --track-origins=yes --error-exitcode=1 --exit-on-first-error=yes
.PHONY: examples test valgrind

ifeq "$(SSL)" "MBEDTLS"
MBEDTLS ?= /usr/local
CFLAGS  += -DMG_ENABLE_MBEDTLS=1 -I$(MBEDTLS)/include -I/usr/include
LDFLAGS ?= -L$(MBEDTLS)/lib -lmbedtls -lmbedcrypto -lmbedx509
endif
ifeq "$(SSL)" "OPENSSL"
OPENSSL ?= /usr/local
CFLAGS  += -DMG_ENABLE_OPENSSL=1 -I$(OPENSSL)/include
LDFLAGS ?= -L$(OPENSSL)/lib -lssl -lcrypto
endif

all: mg_prefix unamalgamated unpacked test test++ valgrind arm examples vc98 vc2017 mingw mingw++ linux linux++ fuzz

examples:
	@for X in $(EXAMPLES); do test -f $$X/Makefile || continue; $(MAKE) -C $$X example || exit 1; done

test/packed_fs.c: Makefile src/ssi.h test/fuzz.c test/data/a.txt
	$(CC) $(CFLAGS) test/pack.c -o pack
	./pack Makefile src/ssi.h test/fuzz.c test/data/a.txt test/data/range.txt > $@

DIR ?= test/data/
OUT ?= fs_packed.c
mkfs:
	$(CC) $(CFLAGS) test/pack.c -o pack
	./pack -s $(DIR) `find $(DIR) -type f` > $(OUT)
#	find $(DIR) -type f | sed -e s,^$(DIR),,g -e s,^/,,g

# Check that all external (exported) symbols have "mg_" prefix
mg_prefix: mongoose.c mongoose.h
	$(CC) mongoose.c $(CFLAGS) -c -o /tmp/x.o && nm /tmp/x.o | grep ' T' | grep -v 'mg_' ; test $$? = 1

# C++ build
test++: CC = g++
test++: C_WARN =
test++: WARN += -Wno-shadow -Wno-missing-field-initializers -Wno-deprecated
test++: test

musl: test
musl: ASAN =
musl: WARN += -Wno-sign-conversion
musl: CC = $(DOCKER) mdashnet/cc1 gcc

# Make sure we can build from an unamalgamated sources
unamalgamated: $(HDRS) Makefile test/packed_fs.c
	$(CC) src/*.c test/packed_fs.c test/unit_test.c $(CFLAGS) $(LDFLAGS) -g -o unit_test

unpacked:
	$(CC) -I. mongoose.c test/unit_test.c -o $@

fuzzer: mongoose.c mongoose.h Makefile test/fuzz.c
	clang++ mongoose.c test/fuzz.c $(WARN) $(INCS) $(TFLAGS) $(EXTRA) -DMG_ENABLE_LINES -fsanitize=fuzzer,signed-integer-overflow,address -Wno-deprecated -o $@

fuzz: fuzzer
	$(RUN) ./fuzzer

unit_test: Makefile mongoose.h $(SRCS)
	$(CC) $(SRCS) $(CFLAGS) -coverage $(LDFLAGS) -g -o unit_test

# make CC=/usr/local/opt/llvm\@8/bin/clang ASAN_OPTIONS=detect_leaks=1
test: unit_test
	ASAN_OPTIONS=$(ASAN_OPTIONS) $(RUN) ./unit_test

coverage: test
	gcov -l -n *.gcno | sed '/^$$/d' | sed 'N;s/\n/ /'
	gcov -t mongoose.c > mongoose.gcov

upload-coverage: coverage
	curl -s https://codecov.io/bash | /bin/bash

valgrind_unit_test: Makefile mongoose.h $(SRCS)
	$(CC) $(SRCS) $(VALGRIND_CFLAGS) -coverage $(LDFLAGS) -g -o valgrind_unit_test

valgrind: valgrind_unit_test
	$(VALGRIND_RUN) ./valgrind_unit_test

infer:
	infer run -- cc test/unit_test.c -c -W -Wall -Werror -Isrc -I. -O2 -DMG_ENABLE_MBEDTLS=1 -DMG_ENABLE_LINES -I/usr/local/Cellar/mbedtls/2.23.0/include  -DMG_ENABLE_IPV6=1 -g -o /dev/null

arm: mongoose.h $(SRCS)
	$(DOCKER) mdashnet/armgcc arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb $(SRCS) test/mongoose_custom.c -Itest -DMG_ARCH=MG_ARCH_NEWLIB $(OPTS) $(WARN) $(INCS) $(DEFS) -o unit_test -nostartfiles --specs nosys.specs -e 0

riscv: mongoose.h $(SRCS)
	$(DOCKER) mdashnet/riscv riscv-none-elf-gcc -march=rv32imc -mabi=ilp32 $(SRCS) test/mongoose_custom.c -Itest -DMG_ARCH=MG_ARCH_NEWLIB $(OPTS) $(WARN) $(INCS) $(DEFS) -o unit_test

#vc98: VCFLAGS += -DMG_ENABLE_IPV6=1
vc98: Makefile mongoose.h $(SRCS)
	$(DOCKER) mdashnet/vc98 wine cl $(SRCS) $(VCFLAGS) ws2_32.lib /Fe$@.exe
	$(DOCKER) mdashnet/vc98 wine $@.exe

#vc2017: VCFLAGS += -DMG_ENABLE_IPV6=1
vc2017: Makefile mongoose.h $(SRCS)
	$(DOCKER) mdashnet/vc2017 wine64 cl $(SRCS) $(VCFLAGS) ws2_32.lib /Fe$@.exe
	$(DOCKER) mdashnet/vc2017 wine64 $@.exe

mingw: Makefile mongoose.h $(SRCS)
	$(DOCKER) mdashnet/mingw i686-w64-mingw32-gcc $(SRCS) -W -Wall -Werror -I. $(DEFS) -lwsock32 -o test.exe
	$(DOCKER) mdashnet/vc98 wine test.exe

mingw++: Makefile mongoose.h $(SRCS)
	$(DOCKER) mdashnet/mingw i686-w64-mingw32-g++ $(SRCS) -W -Wall -Werror -I. $(DEFS) -lwsock32 -o test.exe
  # Note: for some reason, a binary built with mingw g++, fails to run

linux: IPV6=0
linux: Makefile mongoose.h $(SRCS)
	$(DOCKER) mdashnet/cc2 gcc $(SRCS) $(CFLAGS) $(LDFLAGS) -o unit_test_gcc
	$(DOCKER) mdashnet/cc2 ./unit_test_gcc

linux++: CC = g++
linux++: WARN += -Wno-missing-field-initializers
linux++: linux

linux-libs: CFLAGS += -fPIC
linux-libs: mongoose.o
	$(CC) mongoose.o $(LDFLAGS) -shared -o libmongoose.so.$(VERSION)
	$(AR) rcs libmongoose.a mongoose.o

install: linux-libs
	install -Dm644 libmongoose.a libmongoose.so.$(VERSION) $(DESTDIR)$(PREFIX)/lib
	ln -s libmongoose.so.$(VERSION) $(DESTDIR)$(PREFIX)/lib/libmongoose.so
	install -Dm644 mongoose.h $(DESTDIR)$(PREFIX)/include/mongoose.h

uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/lib/libmongoose.a $(DESTDIR)$(PREFIX)/lib/libmongoose.so.$(VERSION) $(DESTDIR)$(PREFIX)/include/mongoose.h $(DESTDIR)$(PREFIX)/lib/libmongoose.so

mongoose.c: Makefile $(wildcard src/*)
	(cat src/license.h; echo; echo '#include "mongoose.h"' ; (for F in src/*.c ; do echo; echo '#ifdef MG_ENABLE_LINES'; echo "#line 1 \"$$F\""; echo '#endif'; cat $$F | sed -e 's,#include ".*,,'; done))> $@

mongoose.h: $(HDRS) Makefile
	(cat src/license.h; echo; echo '#ifndef MONGOOSE_H'; echo '#define MONGOOSE_H'; echo; cat src/version.h ; echo; echo '#ifdef __cplusplus'; echo 'extern "C" {'; echo '#endif'; cat src/arch.h src/arch_*.h src/config.h src/str.h src/log.h src/timer.h src/fs.h src/util.h src/url.h src/iobuf.h src/base64.h src/md5.h src/sha1.h src/event.h src/net.h src/http.h src/ssi.h src/tls.h src/tls_mbed.h src/tls_openssl.h src/ws.h src/sntp.h src/mqtt.h src/dns.h | sed -e 's,#include ".*,,' -e 's,^#pragma once,,'; echo; echo '#ifdef __cplusplus'; echo '}'; echo '#endif'; echo '#endif  // MONGOOSE_H')> $@

clean:
	rm -rf $(PROG) *.o *.dSYM unit_test* valgrind_unit_test* ut fuzzer *.gcov *.gcno *.gcda *.obj *.exe *.ilk *.pdb slow-unit* _CL_* infer-out data.txt crash-* test/packed_fs.c pack unpacked
	@for X in $(EXAMPLES); do test -f $$X/Makefile && $(MAKE) -C $$X clean; done
