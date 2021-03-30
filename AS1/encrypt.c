#include <stdio.h>
#include <stdlib.h>
// #define KEY_LENGTH 6 // Can be anything from 1 to 10

int main(int argc, char** argv ) {
    unsigned char ch;
    FILE *fpIn, *fpOut;
    int KEY_LENTH = atoi(argv[3]);
    // unsigned char key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a};
    // unsigned char key[] = { 0x31, 0xf2, 0x33, 0xe4, 0xc5, 0x06, 0x17, 0x68, 0x99, 0x10}; //r
    unsigned char key[] = { 0x40, 0x12, 0x34, 0x00, 0x01, 0xee, 0xae, 0xc0, 0xd9, 0xff}; //r2

    
    for(int i = 0; i < 10; i++){
        fpIn = fopen(argv[1], "r");
        fpOut = fopen(argv[2], "wb");
        for (int i = 0; fscanf(fpIn, "%c", &ch) != EOF; ++i) {
            ch ^= key[i % KEY_LENTH];
            fwrite(&ch, sizeof(ch), 1, fpOut);
        }
    }

    fclose(fpIn);
    fclose(fpOut);
    return 0;
}