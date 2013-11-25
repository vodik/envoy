#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <err.h>

void safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(strp, fmt, ap) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");
    va_end(ap);
}
