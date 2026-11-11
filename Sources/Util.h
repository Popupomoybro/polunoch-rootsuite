#import <Foundation/Foundation.h>

#ifndef UTIL_H
#define UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

// Shared formatting helper (printf-style -> NSString), used by every module.
static inline NSString *S(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    return s;
}

#ifdef __cplusplus
}
#endif
#endif
