#pragma once

#include "arch.h"
#include "config.h"

enum { MG_LL_NONE, MG_LL_ERROR, MG_LL_INFO, MG_LL_DEBUG, MG_LL_VERBOSE };
void mg_log(const char *fmt, ...) PRINTF_LIKE(1, 2);
bool mg_log_prefix(int ll, const char *file, int line, const char *fname);
void mg_log_set(const char *spec);
void mg_log_set_callback(void (*fn)(const void *, size_t, void *), void *param);
void mg_hexdump(const void *buf, size_t len);

#define MG_LOG(level, args)                                                \
  do {                                                                     \
    if (mg_log_prefix((level), __FILE__, __LINE__, __func__)) mg_log args; \
  } while (0)

#define MG_ERROR(args) MG_LOG(MG_LL_ERROR, args)
#define MG_INFO(args) MG_LOG(MG_LL_INFO, args)
#define MG_DEBUG(args) MG_LOG(MG_LL_DEBUG, args)
#define MG_VERBOSE(args) MG_LOG(MG_LL_VERBOSE, args)
