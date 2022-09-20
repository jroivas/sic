struct tmp {
    int a;
    int b;
};

int func(struct tmp v) {
    return v.a + v.b;
}

int func2(int v[2]) {
    return v[0] + v[1];
}

int main() {
    if (func((struct tmp){5, 9}) != 14)
        return 1;

    int abc[2];
    abc[0] = 1;
    abc[1] = 4;
    if (func2(abc) != 5)
        return 2;

    if (func2((int[2]){40, 2}) != 42)
        return 3;

    return 0;
}
