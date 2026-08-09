// A struct/union/enum *defined* inside a function's return type or a parameter
// (`struct S { ... } *f(void);`) must still register the type so its fields
// resolve. QEMU's omap.h declares `struct omap_dma_lcd_channel_s { ... }
// *omap_dma_get_lcdch(...)` and uses the fields elsewhere.
#include <stdio.h>
enum port { PA, PB };
struct chan { enum port src; long phys[2]; int cond; } *getch(void);
struct outer { struct chan lcd_ch; int y; };
int main(void){
    setvbuf(stdout,0,_IONBF,0);
    struct outer o; struct outer *s = &o;
    s->lcd_ch.src = PB;
    s->lcd_ch.cond = 5;
    s->lcd_ch.phys[0] = 99;
    int ok = (s->lcd_ch.src==PB && s->lcd_ch.cond==5 && s->lcd_ch.phys[0]==99);
    printf("struct-in-func-decl: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
