#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DECODE  1
#define ENCODE  2

char *decode(const char*input, int flag)
{
    char *output = malloc(1024);
    memset(output, 0,1024);
    char tmp[16] = {0};
    int i = 0,j=0;
    int c = 0;

    if (ENCODE == flag) {
        for(i=0; i<strlen(input); i++) {
            c=input[i];
            if (c<128) {
                c+=128;
            }

            if (c>127) {
                c -=128;
            }

            c = 255-c;
            sprintf(tmp, "%02x", c);
            output = strcat(output, tmp);

        }
    } else if(DECODE == flag) {
        for(i=0,j=0; i<strlen(input); i+=2,j++) {
            memset(tmp, 0, 16);
            tmp[0] = input[i];
            tmp[1] = input[i+1];
            c = strtol(tmp, NULL, 16);

//            c = 255 - c;
//            if(c<128){
//                c+=128;
//            }
//            if(c>127)
//            {
//                c-=128;
//            }

            printf("%02x ", c);
            output[j] = (char)c;

        }
        return output;
    }

    return output;

}

int main(int argc, char* argv[])
{

    char *s = decode("70617373776F72642069733A7064666973576964656C7921", DECODE);


    printf("decode:%s\n", s);
    getchar();

    return;
}
