#include<iostream>
using namespace std;

int main(){
	char * s;
	s = (char *)malloc(100);
	char *s2;
	s2 = (char *)malloc(80);
	printf("s addr ->%p\n", &s);
        printf("s2 addr->%p\n", s2);
	malloc(50);
	free(s);
	s = (char *)malloc(100);
	printf("s addr ->%p\n", &s);
	printf("s2 addr->%p\n", s2);
	return 0;
}

