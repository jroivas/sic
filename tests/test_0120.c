// Regression: GCC case-range extension `case LOW ... HIGH:`. sic's parser
// expected a ':' after the case value and rejected the '...'. Used by QEMU
// (e.g. `case DT_ADDRRNGLO ... DT_ADDRRNGHI:`). All values in the range must
// route to the same body.

static int classify(int x)
{
    switch (x) {
        case 0:            return 1;
        case 5 ... 10:     return 2;      // inclusive range
        case 100:          return 3;
        case 200 ... 202:  return 4;
        default:           return -1;
    }
}

int main(void)
{
    if (classify(0) != 1) return 1;
    if (classify(4) != -1) return 2;
    for (int i = 5; i <= 10; i++) if (classify(i) != 2) return 3;
    if (classify(11) != -1) return 4;
    if (classify(100) != 3) return 5;
    if (classify(199) != -1 || classify(203) != -1) return 6;
    if (classify(200) != 4 || classify(201) != 4 || classify(202) != 4) return 7;

    // A range with fall-through into the next case.
    int hits = 0;
    for (int i = 0; i < 5; i++) {
        switch (i) {
            case 1 ... 2:
                hits += 10;
                /* fall through */
            case 3:
                hits += 1;
                break;
            default:
                break;
        }
    }
    // i=1: +10+1; i=2: +10+1; i=3: +1  => 23
    if (hits != 23) return 8;

    return 0;
}
