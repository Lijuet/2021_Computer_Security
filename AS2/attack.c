#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/des.h>

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

    decoding_table = malloc(256);

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

    unsigned char *decoded_data = malloc(*output_length);
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
    char *plainText = NULL, *cipherText = NULL, *encryptedDESText = NULL, *key = NULL;
    char tempKey[2], DESPW[10] = {0}, AESPW[10] = {0};
    unsigned char ** decryptedAESTextList = NULL, **encryptedDESTextList = NULL, **keyList;
    unsigned char ** _encryptedAESTextList = NULL, **_decryptedDESTextList = NULL;
    unsigned char IV[16] ={'\0'};
    int isSame, DESKey, AESKey;
    FILE *fpIn, *fpOut, *fpKey;
    size_t plainTextLen = 0, cipherTextLen = 0, _cipherTextLen = 0, numTotalKey = 184389, decryptedAESTextLen, keyLen;

    //Open key hash file and store them
    fpKey = fopen("passwords.txt", "r");
    keyList = malloc(numTotalKey * sizeof(unsigned char*));
    
    for(int i = 0; i < numTotalKey; i++){
        getline(&key, &keyLen, fpKey);
        keyList[i] = malloc(16 * sizeof(unsigned char));

        for(int j = 0; j < 16; j++){
            strncpy(tempKey, key + (2 * j), 2);
            keyList[i][j] = StringToHexa(tempKey); //change string to hex number
        }
    }
    
    //open input & output file
    fpIn = fopen("PlaintextCiphertext.txt", "r");
    fpOut = fopen("keys.txt", "wb");

    //read plain text
    getline(&plainText, &plainTextLen, fpIn);
    plainTextLen = strlen(plainText);
    
    //read cipher text
    getline(&cipherText, &cipherTextLen, fpIn);
    cipherTextLen = strlen(cipherText);

    printf("CIPHER TEXT(BEFORE ENCODING)\n");
    for(int j = 0; j < cipherTextLen; j++) printf("%d ", (unsigned char) cipherText[j]);
    printf("\n");

    //cipher text is encoded with base64, so decode it
    cipherText = base64_decode(cipherText, cipherTextLen, &_cipherTextLen);
    cipherTextLen = _cipherTextLen;
    
    //TODO: DELETE
    printf("Size of plain text : %ld\nSize of cipher text : %ld\n", plainTextLen, cipherTextLen);

    /**
    * Middle Attack
    * 1. Decrypt cipher text with AES-128 cbc decryption, and store in decryptedAESTextList
    * 2. Encrypt plain text with DES ecb encryption, and store in encryptedDESTextList
    * 3. Compare two arrays and check if there is same decrypted text and encrypted text
    */

    //STEP 1 : Decrypt the cipher text with AES-128-cbc
    //TODO: DELETE
    printf("CIPHER TEXT\n");
    for(int j = 0; j < cipherTextLen; j++) printf("%d ", (unsigned char) cipherText[j]);
    printf("\n");

    AES_KEY dec_key;
    decryptedAESTextLen = cipherTextLen;
    decryptedAESTextList = malloc(numTotalKey * sizeof(char*));

    for (int i = 0; i < numTotalKey; i++){
        //Init
        decryptedAESTextList[i] = malloc(decryptedAESTextLen * sizeof(unsigned char));
        memset(decryptedAESTextList[i], 0, decryptedAESTextLen);
        memset(IV, 0, AES_BLOCK_SIZE);
    
        //Decrypt
        AES_set_decrypt_key(keyList[i], 128, &dec_key); // Size of key is in bits
        AES_cbc_encrypt(cipherText, decryptedAESTextList[i], decryptedAESTextLen, &dec_key, IV, AES_DECRYPT);
        
        //TODO: DELETe
        if(i == 1){
            for(int j = 0; j < decryptedAESTextLen; j++) printf("%d ", (unsigned char)decryptedAESTextList[i][j]);
            printf("\n");
        }
    }

    //TODO: DELETE
    printf("\n\nSize of plain text : %ld\nSize of decrypted text : %ld\n\n", plainTextLen, decryptedAESTextLen);
    printf("\nPlain TEXT\n");
    for(int i = 0; i < plainTextLen; i++) printf("%d ", (unsigned char)plainText[i]);
    printf("\n");

    //STEP 2 : Encrypt the plaint text with DES-ecb
    DES_cblock des_key;
    DES_key_schedule des_keysched;
    encryptedDESTextList = malloc(numTotalKey * sizeof(char*));
   
    for (int i = 0; i < numTotalKey; i++){
        //Init
        encryptedDESTextList[i] = malloc(decryptedAESTextLen * sizeof(char));
        memset(encryptedDESTextList[i], 0, decryptedAESTextLen);

        //Assign Key with only 64 bits
        memcpy(des_key, keyList[i], 8);        
        DES_set_key(&des_key, &des_keysched);

        //Decryption block size is 8 byte
        for (int j = 0; j < decryptedAESTextLen; j += 8) {
            DES_ecb_encrypt((DES_cblock *)(plainText + j), (DES_cblock*)(encryptedDESTextList[i] + j), &des_keysched, DES_ENCRYPT);
        }

        //TODO: DELETE
        if(i == 0){
            for(int k = 0; k < decryptedAESTextLen; k++) printf("%d ", (unsigned char)encryptedDESTextList[i][k]);
            printf("\n");
        }
    }

    //TODO: DELETE
    printf("\nCOMPARE\n");

    //STEP 3 : Compare two results and Check if there are same two arrays
    for(int i = 0; i < numTotalKey; i++){
        for(int j = 0; j < numTotalKey; j++){
            for(int k = 0; k < decryptedAESTextLen; k++){
                if(encryptedDESTextList[i][k] != decryptedAESTextList[j][k]){
                    if (i ==0 && j == 1) printf("DES %d th AES %d th : %d th char not match : %d %d\n", i, j, k, encryptedDESTextList[i][k], decryptedAESTextList[j][k]);
                    break;
                }
                if(k < decryptedAESTextLen) continue;
                
                printf("ENCRYOTED DES : ");
                for(int k = 0; k < decryptedAESTextLen; k++) printf("%d ", encryptedDESTextList[i][k]);
                printf("\nDECRYPTED AES : ");
                for(int k = 0; k < decryptedAESTextLen; k++) printf("%d ", decryptedAESTextList[j][k]);
                printf("\n");

                isSame = 1;
                DESKey = i;
                AESKey = j;
            }     
        }
        if(isSame) break;
    }
    
    //TODO: DELETE
    printf("\nCOMPARE FINISH : %s\n", (isSame)?"EXIST":"NONE");
    printf("DESKey : %d AESKey: %d\n", DESKey, AESKey);

    //Find passwords which generate each keys
    if(isSame){
        rewind(fpKey); //make file cursor point to the front of file
        for(int i = 0; i < numTotalKey; i++){
            getline(&key, &keyLen, fpKey);

            if(i == DESKey) {
                //TODO: DELETE
                printf("D(%d): %s\n", i, key);
                strncpy(DESPW, key + 33, 10);
            }
            if(i == AESKey) {
                //TODO: DELETE
                printf("A(%d): %s\n", i, key);
                strncpy(AESPW, key + 33, 10);
            }
            if(i > DESKey && i > AESKey) break;
        }
        fprintf(fpOut, "%s\n%s", DESPW, AESPW);
    }else {
        printf("There is no key\n");
    }
   
    //Free memory and Close file pointer 
    free(plainText);
    free(cipherText);
    free(decryptedAESTextList);
    free(encryptedDESTextList);
    free(_decryptedDESTextList);
    free(_encryptedAESTextList);
    free(keyList);
    base64_cleanup();

    fclose(fpIn);
    fclose(fpOut);
    fclose(fpKey);
}