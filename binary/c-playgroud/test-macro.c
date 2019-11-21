#define uint unsigned int
#define INT(s) s ##int


int main() {
	INT(u) a = -1;
	printf("%ld\n", a);
	INT() b = -1;
	printf("%ld\n", b);
	int c = -1;
	printf("0x%x\n", c);
}
