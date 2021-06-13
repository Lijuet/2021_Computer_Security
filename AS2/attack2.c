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

void build_decoding_table() {

    decoding_table = (char *)malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

void base64_cleanup() {
    free(decoding_table);
}

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
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
    char *_plainText = NULL, *plainText = NULL, *cipherText = NULL, *key = NULL;
    char tempKey[2], DESPW[10] = {0}, AESPW[10] = {0};
    unsigned char *encryptedAESText = NULL, *encryptedDesText = NULL, **keyList = NULL;
    unsigned char IV[16] ={0}, DESKey[8] = {0}, AESKey[16] = {0};
    int numTotalKey = 184389, isSame = 0, DESKeyIdx, AESKeyIdx;
    FILE *fpIn, *fpOut, *fpKey;
    size_t plainTextLen = 0, cipherTextLen = 0, _cipherTextLen, keyLen = 0, i = 0, finalLen, _finalLen;


    //Open key hash file and store them
    fpKey = fopen("passwords.txt", "r");
    keyList = (unsigned char**)malloc(numTotalKey * sizeof(unsigned char*));
    
    for(int i = 0; i < numTotalKey; i++){
        getline(&key, &keyLen, fpKey);
        keyList[i] = (unsigned char*)malloc(16 * sizeof(unsigned char));

        for(int j = 0; j < 16; j++){
            strncpy(tempKey, key + (2 * j), 2);
            keyList[i][j] = StringToHexa(tempKey); //change string to hex number
        }
    }
    
    //open input & output file
    fpIn = fopen("PlaintextCiphertext.txt", "r");
    fpOut = fopen("keys.txt", "wb");

    //read plain text
    getline(&_plainText, &plainTextLen, fpIn);

    plainTextLen = strlen(_plainText) - 1;
    finalLen = (plainTextLen + DES_BLOCK_SIZE - 1) / DES_BLOCK_SIZE * DES_BLOCK_SIZE;
    finalLen = (finalLen + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;

    plainText = (char*)malloc(finalLen * sizeof(char));
    memset(plainText, 0, finalLen);
    memcpy(plainText, _plainText, plainTextLen);

    //read cipher text
    getline(&cipherText, &cipherTextLen, fpIn);
    cipherTextLen = strlen(cipherText);

    //cipher text is encoded with base64, so decode it
    cipherText = (char *)base64_decode(cipherText, cipherTextLen, &_cipherTextLen);
    cipherTextLen = _cipherTextLen;

    //Init malloc
    encryptedDesText = (unsigned char*)malloc(finalLen * sizeof(char));
    encryptedAESText = (unsigned char*)malloc(finalLen * sizeof(char));

    //STEP 1 : Encrypt the cipher text with DES-ECB
    for(DESKeyIdx = 0, isSame = 0; (DESKeyIdx < numTotalKey) && (isSame == 0); DESKeyIdx++){
        //Init
        memset(encryptedDesText, 0, finalLen);
        
        DES_cblock des_key;
        DES_key_schedule des_keysched;

        //Assign Key with only 64 bits
        memcpy(des_key, keyList[DESKeyIdx], 8);     
        DES_set_key(&des_key, &des_keysched);
        
        //Decryption block size is 8 byte
        for (int j = 0; j < finalLen; j += 8)
            DES_ecb_encrypt((DES_cblock*) (plainText + j), (DES_cblock *)(encryptedDesText + j), &des_keysched, DES_ENCRYPT);

        //STEP 2 : Encrypt the cipher text with AES-128-cbc
        for(AESKeyIdx = 0, isSame = 0; (AESKeyIdx < numTotalKey) && (!isSame); AESKeyIdx++){
            //Init
            AES_KEY enc_key;
            memset(encryptedAESText, 0, finalLen);
            memset(IV, 0, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
            
            //Encrypt
            AES_set_encrypt_key(keyList[AESKeyIdx], 128, &enc_key); // Size of key is in bits
            AES_cbc_encrypt(encryptedDesText, encryptedAESText, finalLen, &enc_key, IV, AES_ENCRYPT);
            
            //Compare encrypted text and ciphertext
            for(int k = 0; k < finalLen; k++){
                if(encryptedAESText[k] != (unsigned char)cipherText[k]) {
                    isSame = 0;
                    break;
                }
                else if(k < finalLen - 1) continue;
                else isSame = 1;
            }
        }
    }

    //Find passwords which generate each keys   
    if(isSame){
        DESKeyIdx--;
        AESKeyIdx--;

        rewind(fpKey); //make file cursor point to the front of file
        for(int i = 0; i < numTotalKey; i++){
            getline(&key, &keyLen, fpKey);

            //Password for DES key
            if(i == DESKeyIdx) {
                strncpy(DESPW, key + 33, 10);
                DESPW[strcspn(DESPW, "\n")] = 0;
            }
            //Password for AES key
            if(i == AESKeyIdx) {
                strncpy(AESPW, key + 33, 10);
                AESPW[strcspn(AESPW, "\n")] = 0;
            }
            if(i > DESKeyIdx && i > AESKeyIdx) break;
        }
        fprintf(fpOut, "%s\n%s", DESPW, AESPW);
    }else {
        fprintf(fpOut, "There is no key\n");
    }
   
    //Free memory and Close file pointer 
    free(_plainText);
    free(plainText);
    free(cipherText);
    free(encryptedDesText);
    free(encryptedAESText);
    free(key);
    free(keyList);

    fclose(fpIn);
    fclose(fpOut);
    fclose(fpKey);
}