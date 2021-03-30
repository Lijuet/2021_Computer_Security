#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

int main(int argc, char** argv){
    unsigned char *buffer = NULL, *key = NULL;
    short freq[256] = {0}, alpaFreq[26] = {0};
    float *squareSumFreqList, squareSumFreq = 0, maxSquareSumFreq = 0, idealSquareSumFreq = 0.0656010;
    float idealAlpaFreq[26] = {0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.02, 0.061, 0.07, 0.002, 0.008, 0.04, 0.024,
                               0.067, 0.075, 0.019, 0.001, 0.06, 0.063, 0.091, 0.028, 0.01, 0.023, 0.001, 0.02, 0.001};
    int maxN, keyLength, keyC;
    size_t size = 0, streamSize = 0, maxUpperCnt, upperCnt;
    FILE *fpIn, *fpOut;

    fpIn = fopen("hw1_input.txt", "r");
    fpOut = fopen("hw1_output.txt", "wb");
 
    //calculate total length of ciphertext
    fseek(fpIn, 0, SEEK_END);
    size = ftell(fpIn);
    rewind(fpIn);

    buffer = malloc((size + 1) * sizeof(unsigned char));
    squareSumFreqList = malloc( 11 * sizeof(float));

    fread(buffer, size, 1, fpIn);
    buffer[size] = '\0';
    
    //Find key length
    for(int N = 10; N >= 1; N--){
        streamSize = 0;

        //count all character and calculate stream length
        for(int i = 0; i < size; i += N){ 
            freq[buffer[i]] += 1;
            streamSize++;
        }

        //calculate sum of qi^2
        for(int i = 0; i < 256; i++)           
            squareSumFreqList[N] += (powf(freq[i], 2) / powf(streamSize, 2));
        

        if(squareSumFreqList[N] > maxSquareSumFreq){
            maxSquareSumFreq = squareSumFreqList[N];
            maxN = N;
        }
        memset(freq, 0, 256 * sizeof(short)); //init
    }

    //reduce key length to smaller one if key length is multiple of original key length
    keyLength = maxN;
    for(int i = maxN - 1; i >= 1; i--)
        if((maxN % i == 0) & (fabs(maxSquareSumFreq - squareSumFreqList[i]) < 0.01)) keyLength = i;
    
    //free useless array
    free(squareSumFreqList);

    //determine key
    key = malloc((keyLength) * sizeof(unsigned char));

    for(int idxKey = 0; idxKey < keyLength; idxKey++){
        maxUpperCnt = 0; //cnt for upper alpabeet
        maxSquareSumFreq = 0;
        key[idxKey] = 0;

        for(int keyC = 0; keyC < 256; keyC++){
            upperCnt = 0;
            squareSumFreq = 0;
            streamSize = 0;

            for(int i = idxKey; i < size; i += keyLength){
                if(isalpha(buffer[i] ^ keyC)) alpaFreq[tolower(buffer[i] ^ keyC) - 'a'] += 1; //count lowercase letters
                if(isupper(buffer[i] ^ keyC)) upperCnt++;
                streamSize++;
            }
            
            //calculate frequency of lowercase letters
            for(int i = 0; i < 26; i++) squareSumFreq += ((float)alpaFreq[i] / streamSize) * idealAlpaFreq[i]; 
            
            if(fabs(squareSumFreq - idealSquareSumFreq) < fabs(maxSquareSumFreq - idealSquareSumFreq)){
                maxSquareSumFreq = squareSumFreq;\
                maxUpperCnt = upperCnt;
                key[idxKey] = keyC;
                
            }
            else if(squareSumFreq == maxSquareSumFreq){
                //In common plaintext, # of lowercase letter is much bigger than uppercase letter
                //solve the side effect of using tolower function to analyze English-letter frequencies
                if(upperCnt < maxUpperCnt) {
                    maxSquareSumFreq = squareSumFreq;
                    maxUpperCnt = upperCnt;
                    key[idxKey] = keyC;
                }
            }
            memset(alpaFreq, 0, 26 * sizeof(short));//init
        }
    }

    //print key and plaintext
    for(int i = 0; i < keyLength; i++)
        fprintf(fpOut, "0x%02x ", key[i]);
    fprintf(fpOut, "\n");

    for(int i = 0; i < size; i ++)
        fprintf(fpOut, "%c", buffer[i] ^ key[i % keyLength]);
     

    //free useless array and close file pointer
    free(buffer);
    fclose(fpIn);
    fclose(fpOut);
}