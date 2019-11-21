#include<stdio.h>
char* ptr_list[100];
int read_num() {
	char input[10];
	int choice;
	if (read(0, input, 10)<0) {
		puts("wrong input");
		return;
	}
	choice = atoi(input);
	return choice;
}
void alloc() {
	puts("how big: ");
	int size = read_num();
	int i;
	char* ptr = malloc(size);
	for(i=0;i<100;i++) {
		if(ptr_list[i]==0) {
			ptr_list[i]=ptr;	
			break;
		}
	}
	if(i==100) {
		puts("alloc failed!!");
	}
}

void w() {
	int id = read_num();
	char* ptr = ptr_list[id];
	if(ptr==0) {
		puts("wrong id!!");
		return;
	}
}
void del() {
	puts("which to delete: ");
	int id = read_num();
	char*ptr = ptr_list[id];
	if(ptr==0) {
		puts("wrong id!!");
		return;
	}
	free(ptr);
	ptr_list[id]=0;
}

void list() {
	puts("===listing....=======");
	for(int i=0;i<100;i++) {
		if(ptr_list[i]!=0) {
			char *ptr = ptr_list[i];
			printf("chunk id: %d \nchunk ptr: 0x%x\n", i, ptr);
			int size = *((long long *)ptr-1);
		        size&= ~0x1;
			int usable_size=malloc_usable_size(ptr);
			printf("chunk size: %d(0x%x)\nchunk usable size: %d(0x%x)\n", size, size, usable_size, usable_size);
			puts("=======================");
		}
	}
} 

void quit() {
	puts("bye!!");
	exit(0);
}

int main() {

	puts("welcome to dame vulnerable heap project.....");
	int choice;
	while(1) {
	puts("---------------------------------------------");
	puts("1. alloc chunk");
	puts("2. write to chunk");
	puts("3. list allocated chunks");
	puts("4: show chunk");
	puts("5: del chunk");
	puts("6: quit");
		puts("input your choice: ");
		choice = read_num();
		printf("choice: %d\n", choice);
		switch(choice) {
			case 1:
				alloc();
				break;
			case 2:
				w();
				break;
			case 3:
				list();
				break;
			case 4:
	//			show();
				break;
			case 5:
				del();
				break;
			case 6:
				quit();
				break;
			default:
				puts("wrong choices");
				break;

		}
	}

}
