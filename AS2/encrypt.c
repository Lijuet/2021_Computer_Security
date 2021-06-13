#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#define DES_BLOCK_SIZE 8

//REF : Base64 Decoding (https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c)
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char*)malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

//REF : change string to HEX (https://kakao-pc.tistory.com/4)
static unsigned char StringToHexa(const char *param)
{
    unsigned char hex = 0;
 
    for(int i = 0; i < 2; i++){
        if(param[i]>= '0' && param[i]<= '9') hex = hex *16 + param[i]- '0';
        else if(param[i]>= 'A' && param[i]<= 'F') hex = hex *16 + param[i]- 'A' + 10;
        else if(param[i]>= 'a' && param[i]<= 'f') hex = hex *16 + param[i]- 'a' + 10;
    }
    return hex;
}


int main(int argc, char** argv ) {
    char *plainText = NULL, *encryptedDESText = NULL, *key = NULL;
    char tempKey[2], DESPW[10] = {0}, AESPW[10] = {0};
    unsigned char *_encryptedAESText = NULL, *_encryptedDESText = NULL, **keyList = NULL;
    unsigned char IV[16] ={'\0'}, DESKey[8] = {0}, AESKey[16] = {0};
    int DESKeyIdx, AESKeyIdx, numTotalKey = 184389;
    FILE *fpIn, *fpOut, *fpKey;
    size_t plainTextLen = 0, cipherTextLen = 0, keyLen = 0, i = 0, finalLen, _finalLen;

    //Open key hash file and store them
    fpKey = fopen("passwords.txt", "r");

    printf("KEY GENEREATION\n");
    srand((unsigned int)time(NULL));
    DESKeyIdx = 3;//rand() % numTotalKey;
    AESKeyIdx = 1;//rand() % numTotalKey;
    printf("%d %d\n", DESKeyIdx, AESKeyIdx);
    
    printf("FIND KEY IDX\n");
    for(int i = 0; i < numTotalKey; i++){
        getline(&key, &keyLen, fpKey);

        if(i == DESKeyIdx){
            for(int j = 0; j < 8; j++){
                strncpy(tempKey, key + (2 * j), 2);
                DESKey[j] = StringToHexa(tempKey); //change string to hex number
                strncpy(DESPW, key + 33, 10);
            }
            printf("DESKEY : %s\n", key);
        }
        if(i == AESKeyIdx){
            for(int j = 0; j < 16; j++){
                strncpy(tempKey, key + (2 * j), 2);
                AESKey[j] = StringToHexa(tempKey); //change string to hex number
                strncpy(AESPW, key + 33, 10);
            }
            printf("AESKEY : %s\n", key);
        }
        if((!DESKeyIdx) && (!AESKeyIdx)) break;
    }
    
    //open input & output file
    fpIn = fopen("plaintext.txt", "r");
    fpOut = fopen("PlaintextCiphertext.txt", "wb");

    //read plain text
    getline(&plainText, &plainTextLen, fpIn);
    plainTextLen = strlen(plainText);
    finalLen = (plainTextLen + DES_BLOCK_SIZE) / DES_BLOCK_SIZE * DES_BLOCK_SIZE;
    printf("%d -> %d ", plainTextLen, finalLen);
    finalLen = (finalLen + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    printf("-> %d\n",finalLen);
    
    //TODO: DELETE
    printf("\nPlain TEXT\n");
    printf("Size of plain text : %ld\n", plainTextLen);
    for(int i = 0; i < plainTextLen; i++) printf("%d ", (unsigned char)plainText[i]);
    printf("\n");


    //DES
    _encryptedDESText = (unsigned char*)malloc((finalLen + 1) * sizeof(char));
    memset(_encryptedDESText, 0, (finalLen + 1));
    
    DES_cblock des_key;
    DES_key_schedule des_keysched;

    //Assign Key with only 64 bits 
    memcpy(des_key, DESKey, 8);    
    DES_set_key(&des_key, &des_keysched);

    for (int j = 0; j < finalLen; j += 8) {
        DES_ecb_encrypt((DES_cblock*) (plainText + j), (DES_cblock *)(_encryptedDESText + j), &des_keysched, DES_ENCRYPT);
    }


    printf("DES CIPHER TEXT\n");
    for(int j = 0; j < finalLen; j++) printf("%d ", _encryptedDESText[j]);
    printf("\n");


    //AES
    AES_KEY enc_key;
    _encryptedAESText = (unsigned char*)malloc((finalLen + 1) * sizeof(char));
    memset(_encryptedAESText, 0, finalLen);

    memset(IV, 0, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly

    AES_set_encrypt_key(AESKey, 128, &enc_key); // Size of key is in bits
    AES_cbc_encrypt(_encryptedDESText, _encryptedAESText, finalLen, &enc_key, IV, AES_ENCRYPT);
    


    printf("AES CIPHER TEXT\n");
    for(int j = 0; j < finalLen; j++) printf("%d ", (unsigned char) _encryptedAESText[j]);
    printf("\n");

    _encryptedAESText = base64_encode(_encryptedAESText, finalLen, &_finalLen);
    printf("Before Encoded : %ld After Encoding : %ld\n", finalLen, _finalLen);

    
    printf("Encoded TEXT\n");
    for(int j = 0; j < _finalLen; j++) printf("%d ", _encryptedAESText[j]);
    printf("\n");
    for(int j = 0; j < _finalLen; j++) printf("%c ", _encryptedAESText[j]);
    printf("\n");
    fprintf(fpOut, "%s\n", plainText);
    for(int k = 0; k < _finalLen; k++) fprintf(fpOut, "%c", _encryptedAESText[k]);
    printf("\n");
   
    //Free memory and Close file pointer 
    free(plainText);
    free(_encryptedDESText);
    free(_encryptedAESText);
    free(keyList);

    fclose(fpIn);
    fclose(fpOut);
    fclose(fpKey);
}