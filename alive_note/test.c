#include<stdio.h>

int main(){
	
	char a[] = "abcdef";
	printf("%x\n", (char *)a-8);
	a[-1] = 'v';
	printf("%x\n", a[-1]);
	char * b = (long)a - 1;
	printf("%s", b);
	return 0;


}

