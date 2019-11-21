#include<stdio.h>

int main()
{
    char *gap;

    char *ptr0=malloc(0x400-0x10); //A
    gap=malloc(0x10);
    char *ptr1=malloc(0x410-0x10); //B
    gap=malloc(0x10);
    char *ptr2=malloc(0x420-0x10); //C
    gap=malloc(0x10);
    char *ptr3=malloc(0x430-0x10); //D
    gap=malloc(0x10);
    char *ptr4=malloc(0x400-0x10); //E
    gap=malloc(0x10);
    char *ptr5=malloc(0x410-0x10); //F
    gap=malloc(0x10);
    char *ptr6=malloc(0x420-0x10); //G
    gap=malloc(0x10);
    char *ptr7=malloc(0x430-0x10); //H
    gap=malloc(0x10);
printf("ptr0: %p, ptr1: %p, ptr2: %p, ptr3: %p,   ptr4: %p, ptr5: %p, ptr6: %p, ptr7: %p\n",ptr0,ptr1,ptr2,ptr3,ptr4,ptr5,ptr6,ptr7);

    free(ptr2); //C
    free(ptr3); //D
//    free(ptr0); //A
 //   free(ptr1); //B
    free(ptr7); //H
    free(ptr6); //G
   // free(ptr5); //F
  //  free(ptr4); //E

    malloc(0x440); //trigger that sort largebin from unsorted bin to largebins

    return 0;
}
