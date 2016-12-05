/**
 * MassClone - A simple tool to clone a box of Pokemon, written in C
 *
 * Save file structure and CRC-16 code are taken from PKHeX.
 * Memecrypto code are taken from SciresM's memecrypto_test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <conio.h>
#endif

#define MEME_LEN 0x60
#define PUBKEYDER_LEN 0x7E
#define RSA_BITS 768
#define RSA_BYTES (RSA_BITS / 8)
#define GAME_COUNT 3

struct game_info_t {
    int save_size;
    int box_offset;
    int box_size;
    int box_max;
};
struct game_info_t game_info[GAME_COUNT] = {
    {0x65600, 0x22600, 0x1B30, 31},
    {0x76000, 0x33000, 0x1B30, 31},
    {0x6BE00, 0x04E00, 0x1B30, 32}
};
enum game_e {XY, ORAS, SM};

static unsigned char pubkeyder[] = {
    0x30, 0x7C, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x6B, 0x00, 0x30, 0x68, 0x02, 0x61,
    0x00, 0xB6, 0x1E, 0x19, 0x20, 0x91, 0xF9, 0x0A, 0x8F, 0x76, 0xA6, 0xEA,
    0xAA, 0x9A, 0x3C, 0xE5, 0x8C, 0x86, 0x3F, 0x39, 0xAE, 0x25, 0x3F, 0x03,
    0x78, 0x16, 0xF5, 0x97, 0x58, 0x54, 0xE0, 0x7A, 0x9A, 0x45, 0x66, 0x01,
    0xE7, 0xC9, 0x4C, 0x29, 0x75, 0x9F, 0xE1, 0x55, 0xC0, 0x64, 0xED, 0xDF,
    0xA1, 0x11, 0x44, 0x3F, 0x81, 0xEF, 0x1A, 0x42, 0x8C, 0xF6, 0xCD, 0x32,
    0xF9, 0xDA, 0xC9, 0xD4, 0x8E, 0x94, 0xCF, 0xB3, 0xF6, 0x90, 0x12, 0x0E,
    0x8E, 0x6B, 0x91, 0x11, 0xAD, 0xDA, 0xF1, 0x1E, 0x7C, 0x96, 0x20, 0x8C,
    0x37, 0xC0, 0x14, 0x3F, 0xF2, 0xBF, 0x3D, 0x7E, 0x83, 0x11, 0x41, 0xA9,
    0x73, 0x02, 0x03, 0x01, 0x00, 0x01
};
static unsigned char modulus[] = {
    0xB6, 0x1E, 0x19, 0x20, 0x91, 0xF9, 0x0A, 0x8F, 0x76, 0xA6, 0xEA, 0xAA,
    0x9A, 0x3C, 0xE5, 0x8C, 0x86, 0x3F, 0x39, 0xAE, 0x25, 0x3F, 0x03, 0x78,
    0x16, 0xF5, 0x97, 0x58, 0x54, 0xE0, 0x7A, 0x9A, 0x45, 0x66, 0x01, 0xE7,
    0xC9, 0x4C, 0x29, 0x75, 0x9F, 0xE1, 0x55, 0xC0, 0x64, 0xED, 0xDF, 0xA1,
    0x11, 0x44, 0x3F, 0x81, 0xEF, 0x1A, 0x42, 0x8C, 0xF6, 0xCD, 0x32, 0xF9,
    0xDA, 0xC9, 0xD4, 0x8E, 0x94, 0xCF, 0xB3, 0xF6, 0x90, 0x12, 0x0E, 0x8E,
    0x6B, 0x91, 0x11, 0xAD, 0xDA, 0xF1, 0x1E, 0x7C, 0x96, 0x20, 0x8C, 0x37,
    0xC0, 0x14, 0x3F, 0xF2, 0xBF, 0x3D, 0x7E, 0x83, 0x11, 0x41, 0xA9, 0x73
};
static unsigned char privexp[] = {
    0x77, 0x54, 0x55, 0x66, 0x8F, 0xFF, 0x3C, 0xBA, 0x30, 0x26, 0xC2, 0xD0,
    0xB2, 0x6B, 0x80, 0x85, 0x89, 0x59, 0x58, 0x34, 0x11, 0x57, 0xAE, 0xB0,
    0x3B, 0x6B, 0x04, 0x95, 0xEE, 0x57, 0x80, 0x3E, 0x21, 0x86, 0xEB, 0x6C,
    0xB2, 0xEB, 0x62, 0xA7, 0x1D, 0xF1, 0x8A, 0x3C, 0x9C, 0x65, 0x79, 0x07,
    0x76, 0x70, 0x96, 0x1B, 0x3A, 0x61, 0x02, 0xDA, 0xBE, 0x5A, 0x19, 0x4A,
    0xB5, 0x8C, 0x32, 0x50, 0xAE, 0xD5, 0x97, 0xFC, 0x78, 0x97, 0x8A, 0x32,
    0x6D, 0xB1, 0xD7, 0xB2, 0x8D, 0xCC, 0xCB, 0x2A, 0x3E, 0x01, 0x4E, 0xDB,
    0xD3, 0x97, 0xAD, 0x33, 0xB8, 0xF2, 0x8C, 0xD5, 0x25, 0x05, 0x42, 0x51
};
static unsigned char pubexp[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
};

// CRC16-CCITT, used in Pokemon X / Y / Omega Ruby / Alpha Sapphire
unsigned short crc16_ccitt(char* data, int length){
    unsigned short crc = 0xFFFF;
    int i, j;

    for (i = 0; i < length; i++){
        crc ^= data[i] << 8;
        for (j = 0; j < 8; j++){
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }

    return crc;
}

// CRC16 for Pokemon Sun / Moon, implemented using reflected polynomial
unsigned short crc16_ref(char *data, int length){
    unsigned short crc = 0xFFFF, tmp;
    int i, j;

    for (i = 0; i < length; i++){
        tmp = (data[i] ^ crc) & 0xFF;
        for (j = 0; j < 8; j++)
            if (tmp & 0x1)
                tmp = (tmp >> 1) ^ 0xA001;
            else
                tmp >>= 1;
        crc = tmp ^ crc >> 8;
    }

    return ~crc;
}

void xor(unsigned char *in, unsigned char *b, int len){
    int i;
    for (i = 0; i < len; i++)
        in[i] ^= b[i];
}

void memecrypto_aes_encrypt(unsigned char *buf, unsigned char *output,
                            unsigned char *key){
    unsigned char temp[0x10];
    unsigned char temp2[0x10];
    unsigned char subkey[0x10];
    unsigned char block[0x10];
    int i;
    AES_KEY aes_key;

    AES_set_encrypt_key(key, 128, &aes_key);

    // AES-CBC
    for (i = 0; i < 0x10; i++)
        temp[i] = 0;
    AES_cbc_encrypt(buf, output, MEME_LEN, &aes_key, temp, AES_ENCRYPT);

    // CMAC
    memcpy(temp, output + MEME_LEN - 0x10, 0x10);
    xor(temp, output, 0x10);
    i = 0;
    while (i < 0xF){
        subkey[i] = (temp[i] << 1) | (temp[i + 1] >> 7);
        i++;
    }
    subkey[0xF] = temp[0xF] << 1;
    if (temp[0] & 0x80)
        subkey[0xF] ^= 0x87;

    // AES-PBC
    for (i = 0; i < 0x10; i++)
        temp[i] = 0;
    for (i = MEME_LEN - 0x10; i >= 0; i -= 0x10){
        memcpy(block, output + i, 0x10);
        xor(block, subkey, 0x10);
        AES_ecb_encrypt(block, temp2, &aes_key, AES_ENCRYPT);
        xor(temp2, temp, 0x10);
        memcpy(output + i, temp2, 0x10);
        memcpy(temp, block, 0x10);
    }
}

void memecrypto_aes_decrypt(unsigned char *buf, unsigned char *output,
                            unsigned char *key){
    unsigned char temp[0x10];
    unsigned char subkey[0x10];
    unsigned char block[0x10];
    unsigned char temp_cbc[MEME_LEN];
    int i;
    AES_KEY aes_key;

    AES_set_decrypt_key(key, 128, &aes_key);

    // AES-PBC
    for (i = 0; i < 0x10; i++)
        temp[i] = 0;
    for (i = MEME_LEN - 0x10; i >= 0; i -= 0x10){
        memcpy(block, buf + i, 0x10);
        xor(block, temp, 0x10);
        AES_ecb_encrypt(block, temp, &aes_key, AES_DECRYPT);
        memcpy(output + i, temp, 0x10);
    }

    // CMAC
    memcpy(temp, output + MEME_LEN - 0x10, 0x10);
    xor(temp, output, 0x10);
    i = 0;
    while (i < 0xF){
        subkey[i] = (temp[i] << 1) | (temp[i + 1] >> 7);
        i++;
    }
    subkey[0xF] = temp[i] << 1;
    if (temp[0] & 0x80)
        subkey[0xF] ^= 0x87;

    for (i = 0; i < MEME_LEN; i += 0x10)
        xor(output + i, subkey, 0x10);

    for (i = 0; i < 0x10; i++)
        temp[i] = 0;
    AES_cbc_encrypt(output, temp_cbc, MEME_LEN, &aes_key, temp, AES_DECRYPT);
    memcpy(output, temp_cbc, MEME_LEN);
}

int memecrypto_sign(unsigned char *input, unsigned char *output, int len){
    unsigned char memebuf[MEME_LEN];
    unsigned char hash[0x14];
    SHA_CTX sha_ctx;
    RSA *rsa;

    if (len < MEME_LEN)
        return 0;

    memcpy(output, input, len - MEME_LEN);

    SHA1(input, len - 8, hash);
    memcpy(input + len - 8, hash, 8); // Update SHA1 hash

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, pubkeyder, PUBKEYDER_LEN);
    if (len > MEME_LEN)
        SHA1_Update(&sha_ctx, input, len - MEME_LEN);
    SHA1_Final(hash, &sha_ctx);

    memcpy(memebuf, input + (len - MEME_LEN), MEME_LEN);
    memecrypto_aes_encrypt(memebuf, memebuf, hash);
    memebuf[0x0] &= 0x7F;

    // RSA
    rsa = RSA_new();
    rsa->n = BN_bin2bn(modulus, RSA_BYTES, NULL);
    rsa->d = BN_bin2bn(privexp, RSA_BYTES, NULL);
    rsa->e = BN_bin2bn(pubexp, RSA_BYTES, NULL);
    RSA_private_encrypt(MEME_LEN, memebuf, output + (len - MEME_LEN), rsa,
        RSA_NO_PADDING);
    RSA_free(rsa);
    return 1;
}

int memecrypto_verify(unsigned char *input, unsigned char *output, int len){
    unsigned char memebuf_1[MEME_LEN];
    unsigned char memebuf_2[MEME_LEN];
    unsigned char hash[0x14];
    SHA_CTX sha_ctx;
    RSA *rsa;

    if (len < MEME_LEN)
        return 0;

    memcpy(output, input, len - MEME_LEN);

    // RSA
    rsa = RSA_new();
    rsa->n = BN_bin2bn(modulus, RSA_BYTES, NULL);
    rsa->d = BN_bin2bn(privexp, RSA_BYTES, NULL);
    rsa->e = BN_bin2bn(pubexp, RSA_BYTES, NULL);
    RSA_public_decrypt(MEME_LEN, input + (len - MEME_LEN), memebuf_1, rsa,
        RSA_NO_PADDING);
    RSA_free(rsa);

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, pubkeyder, PUBKEYDER_LEN);
    if (len > MEME_LEN)
        SHA1_Update(&sha_ctx, input, len - MEME_LEN);
    SHA1_Final(hash, &sha_ctx); // Hash is now aes key

    memcpy(memebuf_2, memebuf_1, MEME_LEN);
    memebuf_2[0] |= 0x80;
    memecrypto_aes_decrypt(memebuf_1, memebuf_1, hash);
    memecrypto_aes_decrypt(memebuf_2, memebuf_2, hash);

    // Try memebuf_1
    memcpy(output + (len - MEME_LEN), memebuf_1, MEME_LEN);
    SHA1(output, len - 8, hash);
    if (!memcmp(hash, output + len - 8, 8))
        return 1;

    // Try memebuf_2
    memcpy(output + (len - MEME_LEN), memebuf_2, MEME_LEN);
    SHA1(output, len - 8, hash);
    if (!memcmp(hash, output + len - 8, 8))
        return 1;

    return 0;
}

int main(int argc, char **argv){
    FILE *f;
    long length;
    int boxa, boxb;
    char agree;
    char *boxdata;
    struct game_info_t info;
    enum game_e game;
    int storage_size = 0;

    printf("MassClone v2.0 - written by RainThunder\n\n");

    // Argument check
    if (argc == 1){
        printf("Syntax: MassClone filename\n");
#ifdef _WIN32
        getch();
#endif
        return 0;
    }

    f = fopen(argv[1], "r+b");
    fseek(f, 0, SEEK_END);
    length = ftell(f);
    while ((game < GAME_COUNT) && (game_info[game].save_size != length)) game++;
    if (game == GAME_COUNT){
        printf("Unsupported file size: %d\n", length);
#ifdef _WIN32
        getch();
#endif
        return 0;
    }
    info = game_info[game];

    // Input prompt
    printf("Input the first box number: ");
    scanf("%d", &boxa);
    printf("Input the second box number: ");
    scanf("%d", &boxb);
    printf("If there are any pokemon in the second box, they will be deleted.\nContinue? (Y/N) ");
    while (1){
        agree = getchar();
        if ((agree == 'N') || (agree == 'n')) return 0;
        if ((agree == 'Y') || (agree == 'y')) break;
    }
    printf("\n");

    // Read
    storage_size = info.box_size * info.box_max;
    fseek(f, info.box_offset, SEEK_SET);
    boxdata = (char *)malloc(storage_size);
    fread(boxdata, sizeof(char), storage_size, f);

    // Clone
    memcpy(boxdata + (boxb - 1) * info.box_size,
        boxdata + (boxa - 1) * info.box_size,
        info.box_size);

    // Write box data
    fseek(f, info.box_offset, SEEK_SET);
    fwrite(boxdata, sizeof(char), storage_size, f);

    // Calculate and write checksums
    if (game == XY){
        unsigned short checksum = crc16_ccitt(boxdata, storage_size);
        fseek(f, 0x655C2, SEEK_SET);
        fwrite(&checksum, 2, 1, f);
    }
    else if (game == ORAS){
        unsigned short checksum = crc16_ccitt(boxdata, storage_size);
        fseek(f, 0x75FDA, SEEK_SET);
        fwrite(&checksum, 2, 1, f);
    }
    else { // SM
        unsigned short checksum = crc16_ref(boxdata, storage_size);
        char current_sig[0x80];
        char checksum_table[0x140];
        char decrypted_sig[0x80];
        char hash[0x20];
        int i;

        // Box data checksum
        fseek(f, 0x6BC8A, SEEK_SET);
        fwrite(&checksum, sizeof(unsigned short), 1, f);

        // Save signature
        fseek(f, 0x6BB00, SEEK_SET);
        fread(current_sig, sizeof(char), 0x80, f);
        fseek(f, 0x6BC00, SEEK_SET);
        fread(checksum_table, sizeof(char), 0x140, f);
        if (!memecrypto_verify(current_sig, decrypted_sig, 0x80))
            for (i = 0x20; i < 0x80; i++)
                decrypted_sig[i] = 0;
        SHA256(checksum_table, 0x140, hash);
        memcpy(decrypted_sig, hash, 0x20);
        memecrypto_sign(decrypted_sig, current_sig, 0x80);
        fseek(f, 0x6BB00, SEEK_SET);
        fwrite(current_sig, sizeof(char), 0x80, f);
    }

    free(boxdata);
    fclose(f);
    printf("Done.");
#ifdef _WIN32
    getch();
#endif
    return 0;
}

