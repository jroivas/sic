/* C: a declaration right after a case label belongs to the switch block — the
   statements after it use it (was "undefined name 'tmp'"). */
int f(int x)
{
    int r = 0;
    switch (x) {
    case 2:
        int tmp = x;
        r = 222 + tmp;
        break;
    case 3:
        r = 3;
        break;
    }
    return r;
}

int main(void) { return f(2) == 224 && f(3) == 3 ? 42 : 1; }
