#include <windows.h>
#include <cstdio>
int main(){FILE* f=nullptr;fopen_s(&f,"entry-ran.txt","wb");if(f){fputs("entry\n",f);fclose(f);}return 0;}
