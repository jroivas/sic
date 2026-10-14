/* A scalar floating global initialized from an integer constant expression
 * (`double x = 100;`) stored the integer's bit pattern (x was 4.9e-322), and
 * float constant expressions (`1.0 / 3`) were left zero. c-testsuite 00119.
 * Returns 42. */
double x = 100;
float f = 3;
double z = -7;
double e = 1 + 2;
double c = 'A';
double h = 10 / 4;            /* integer division first: 2 */
double a = 2.5 * 2;
double third = 1.0 / 3;
double fl = (float)0.1;
double arr[3] = { 2.5 * 2, 7 / 2, 1 / 2.0 };
int main(void) {
    if (x != 100.0 || f != 3.0f || z != -7.0 || e != 3.0 || c != 65.0) return 1;
    if (h != 2.0 || a != 5.0 || third != 1.0 / 3 || fl != (double)(float)0.1) return 2;
    if (arr[0] != 5.0 || arr[1] != 3.0 || arr[2] != 0.5) return 3;
    if (x < 1) return 4;
    return 42;
}
