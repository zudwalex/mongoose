#pragma once

#if MG_ARCH == MG_ARCH_ZEPHYR

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <net/socket.h>
#include <posix/time.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define MBEDTLS_FS_IO

#endif
