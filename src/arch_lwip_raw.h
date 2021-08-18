#pragma once

#if MG_ARCH == MG_ARCH_LWIP_RAW

#undef MG_ENABLE_SOCKET
#define MG_ENABLE_SOCKET 0

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <lwip/opt.h>
#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/dns.h>
#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>

#ifndef LWIP_PROVIDE_ERRNO
#include <errno.h>
#else
#include <lwip/errno.h>
#endif

#if defined(LWIP_SOCKET) && LWIP_SOCKET == 1
#error Wrong MG_ARCH, use MG_ARCH_FREERTOS_LWIP for LWIP/sockets 
#endif

#define INVALID_SOCKET (-1)
#define SOMAXCONN 10
typedef int sock_t;

struct mg_mgr;
struct mg_connection;
void mg_lwip_set_keepalive_params(struct mg_connection *nc, int idle,
                                  int interval, int count);

#define MG_INT64_FMT "%lld"
#define MG_DIRSEP '/'

#endif
