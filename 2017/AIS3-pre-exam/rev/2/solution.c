#include <stdio.h>
#include <stdlib.h> /* 亂數相關函數 */
#include <time.h>   /* 時間相關函數 */
#include <string.h>
#define t 1498406400


char encrypt[] = "\x78\x66\xe6\x2b\x4a\x3c\x9a\x7b\x9f"
                 "\xe6\x4b\xd2\xac\xd5\x1e\xfe\x4f\xa8"
                 "\x91\xcd\x6c\xc0\x6d\x25";
void pflag(int sed)
{
    char flag[25];
    flag[24] = '\0';
    srand(sed);
	int len = strlen(encrypt);
	int i, x;
	for(i = 0; i < len; i++)
    {
        x = rand();
        if(i < 5 && sed == t) printf("%d\n", x);
        flag[i] = (x ^ encrypt[i]) & 0xff;
    }
    printf("%s\n", flag);
}

int main()
{
    int i;
    int a = 24 * 60 * 60 * 1;
    for(i = 0; i <= a; i++)
    {
        pflag(t + i);
    }
	return 0;
}
