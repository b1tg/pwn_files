#include <stdio.h>
int g_v;

int g_init_v = 21;

void fun() {
	int stack_var;
	printf("stack var in fun is at %p\n", &stack_var);
}

int main() {
	int stack_var;
	static int static_init_v = 12;
	static int static_v;
	int *heap_v_ptr;
	
	heap_v_ptr = (int *) malloc(4);
	printf("g init value is as %p\n", &g_init_v);
	printf("g uninit value is as %p\n", &g_v);
	printf("stack var in main is at %p\n",&stack_var);
	printf("static init value is at %p\n", &static_init_v);
	printf("static uninit value is at %p\n", &static_v);
	printf("heap ptr is 0x%lx, at %p\n", heap_v_ptr, &heap_v_ptr);
	fun();

}
