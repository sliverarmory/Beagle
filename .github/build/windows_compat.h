/* MinGW distributions do not all provide POSIX strndup. Keep the pinned
 * GraphQLite source unchanged and supply the same bounded-copy behavior. */
#ifndef BEAGLE_WINDOWS_COMPAT_H
#define BEAGLE_WINDOWS_COMPAT_H

#ifdef _WIN32
#include <stdlib.h>
#include <string.h>

static inline char *beagle_strndup(const char *text, size_t limit)
{
    size_t length = 0;
    while (length < limit && text[length])
        length++;
    char *copy = (char *)malloc(length + 1);
    if (copy) {
        memcpy(copy, text, length);
        copy[length] = '\0';
    }
    return copy;
}

#define strndup beagle_strndup
#endif
#endif
