#include<stdio.h>

int main(){
    char data[20];
    FILE*fp=fopen("test","rb");
    fread(data,1,20,fp);
    return 0;
}
