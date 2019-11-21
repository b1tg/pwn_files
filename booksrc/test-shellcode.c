#include <unistd.h>
void vuln(char *sss) {
	char buffer[16];
//	buffer = argv;
	strcpy(buffer, sss);
	puts(buffer);
	//read(0, buffer, 100);

}
int main(int argc, char *argv[]) {
	vuln(argv[1]);
}
