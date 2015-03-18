#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Copyright 2015 by RainThunder
 */

char* ccitt16(char* data, int length){
    short crc = 0xFFFF;
    char* chk;
    int i, j;
    
    for (i = 0; i < length; i++)
    {
        crc ^= data[i] << 8;
        for (j = 0; j < 8; j++)
        {
            if ((crc & 0x8000) > 0)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    
    chk = malloc(2*sizeof(char));
    chk[1] = crc >> 8;
    chk[0] = crc & 0xFF;
    return chk;
}

int main(int argc, char **argv){
    FILE *f;
    long length;
    int boxa, boxb;
    char agree;
    char boxdata[0x34AD0];
    char* checksum;
    
    // Argument Check
    if (argc == 1){
        printf("Syntax: MassClone filename");
        getch();
        return 0;
    }
    
    f = fopen(argv[1], "r+b");
    fseek(f, 0, SEEK_END);
    length = ftell(f);
    if ((length != 0x65600) && (length != 0x76000)){
        printf("Wrong file size: %d", length);
        getch();
        return 0;
    }
    
    printf("Input the first box number: ");
    scanf("%d", &boxa);
    printf("Input the second box number: ");
    scanf("%d", &boxb);
    printf("If there are any pokemon in the second box, they will be deleted.\nContinue? (Y/N) ");
    agree = getch();
    if ((agree == 'N') || (agree == 'n')) return 0;
    
    if (length == 0x65600){
        /*
        fseek(f, 0x22600 + (boxa - 1) * 0x1B30, SEEK_SET);
        fread(boxdata, 1, 0x1B30, f); // Read 0x1B30 * 1 bytes from f to boxdata
        fseek(f, 0x22600 + (boxb - 1) * 0x1B30, SEEK_SET);
        fwrite(boxdata, 1, 0x1B30, f);
        */
        fseek(f, 0x22600, SEEK_SET);
        fread(boxdata, 1, 0x34AD0, f);
        // memcpy( void * dest, const void * src, size_t count )
        memcpy(boxdata + (boxb - 1) * 0x1B30, boxdata + (boxa - 1) * 0x1B30, 0x1B30);
        checksum = ccitt16(boxdata, 0x34AD0);
        fseek(f, 0x22600, SEEK_SET);
        fwrite(boxdata, 1, 0x34AD0, f);
        fseek(f, 0x655C2, SEEK_SET);
        fwrite(checksum, 1, 2, f);
    }
    else {
        fseek(f, 0x33000, SEEK_SET);
        fread(boxdata, 1, 0x34AD0, f);
        memcpy(boxdata + (boxb - 1) * 0x1B30, boxdata + (boxa - 1) * 0x1B30, 0x1B30);
        checksum = ccitt16(boxdata, 0x34AD0);
        fseek(f, 0x33000, SEEK_SET);
        fwrite(boxdata, 1, 0x34AD0, f);
        fseek(f, 0x75FDA, SEEK_SET);
        fwrite(checksum, 1, 2, f);
    }
    
    printf("Done.");
    getch();
    return 0;
}

