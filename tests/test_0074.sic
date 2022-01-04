typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static inline uint16_t bswap16(uint16_t b)
{
  return __builtin_bswap16(b);
}

static inline uint32_t bswap32(uint32_t b)
{
  return __builtin_bswap32(b);
}

static inline uint64_t bswap64(uint64_t b)
{
  return __builtin_bswap64(b);
}

int printf(const char *fmt, ...);

int main()
{
    uint16_t v16 = 0x1234;
    v16 = bswap16(v16);
    if (v16 != 0x3412)
        return 1;

    if (bswap32(0x12345678) != 0x78563412)
        return 2;

    if (bswap64(0x1234567890abcdef) != 0xefcdab9078563412)
        return 3;

    return 0;
}
