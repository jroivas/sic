// Types shared by va_callee.c and va_caller.c.
typedef struct { long a; } V8;
typedef struct { long a, b; } V16;
typedef struct { long a, b, c; } V24;
typedef struct { char a[3]; } V3;
typedef struct { double d; } VD;
typedef struct { double d; long l; } VDL;
typedef struct { float a, b; } VFF;
typedef union { long l; double d; } VU;
