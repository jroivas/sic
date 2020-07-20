#pragma once

extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function);

#define assert(X) \
    ((X) ? (void) (0) :__assert_fail (#X, __FILE__, __LINE__, __PRETTY_FUNCTION__));
