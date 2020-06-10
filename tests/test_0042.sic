int main()
{
    int arr[10];
    int c = 5;
    int d = 1;
    int arr2[c];

    arr[0] = 1;

    if (arr[0] != 1)
        return 1;

    for (int i = 0; i < 10; i++) {
        arr[i] = i * 2;
    }
    if (arr[0] == 1)
        return 2;
    if (arr[5] != 10)
        return 3;
    if (arr[8] != 16)
        return 4;

    for (int i = 0; i < c; i++)
        arr2[i] = (i << 1) * i;

    if (arr2[c - 1] != 32)
        return 5;
    if (arr2[2] != 8)
        return 6;
    if (arr2[0] != 0)
        return 7;

    // Should be 2 now, c - d == 3
    d++;
    if (arr2[c - d] != 18)
        return 8;
    // Should be 5 - (2 - 1) * 2 = 3
    if (arr2[c - (d - 1) * 2] != 18)
        return 9;
    // Should be 5 * 2 - (2 + 1) * 2 = 4
    if (arr2[c * 2- (d + 1) * 2] != 32)
        return 10;

    // arr[1] == 2, arr2[2] == 8
    if (arr2[arr[1]] != 8)
        return 11;
    // arr[2] == 4, arr2[4] == 32
    if (arr2[arr[2]] != 32)
        return 12;

    // arr[1] == 2, arr2[2] == 8, arr[8] == 16
    if (arr[arr2[arr[1]]] != 16)
        return 13;
    // arr[1] == 2, arr2[2] == 8, arr[8/2] == 8
    if (arr[arr2[arr[1]] / 2] != 8)
        return 14;

    arr[arr2[arr[1]] / 2] = 9;
    if (arr[4] == 8)
        return 15;
    if (arr[4] != 9)
        return 16;

    return 0;
}
