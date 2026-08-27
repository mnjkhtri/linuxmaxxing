#include <stdio.h>

#if defined(USER)

extern void bubble_sort(long *arr, long n);

int main()
{
    long array[] = {4, 2, 6, 3, 5, 7, 8, 1, 4, 9};
    int n = 10;

    printf("Before: ");
    for (int i = 0; i < n; i++)
        printf("%ld ", array[i]);

    bubble_sort(array, n);

    printf("\nAfter:  ");
    for (int i = 0; i < n; i++)
        printf("%ld ", array[i]);
    printf("\n");

    return 0;
}

#elif defined(SIMD)

extern void vector_add_avx2(const int *a, const int *b, int *out, long n);

static void print_array(const char *label, const int *array, long n)
{
    printf("%s", label);
    for (long i = 0; i < n; i++)
        printf("%d ", array[i]);
    printf("\n");
}

int main()
{
    int a[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int b[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int out[10] = {0};
    long n = 10;

    vector_add_avx2(a, b, out, n);

    print_array("A:   ", a, n);
    print_array("B:   ", b, n);
    print_array("Sum: ", out, n);

    return 0;
}

#else
#error "Define one main program: USER or SIMD"
#endif
