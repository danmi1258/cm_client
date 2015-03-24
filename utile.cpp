/*
 * utile.cpp
 *
 *  Created on: Feb 25, 2015
 *      Author: root
 */

#include<stdio.h>
#include <memory.h>
#include<stdlib.h>
#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "openssl/evp.h"

#define ETH_ALEN	6
#define MAC_FORMAT_STRING "%02x-%02x-%02x-%02x-%02x-%02x"

unsigned char *char_bin_to_str(unsigned char data)
{
	unsigned char *buf;
	buf = (unsigned char*)malloc(2);
	unsigned char hi,lo;

	hi = (data >> 4) & 0x0f;
	lo = data & 0x0f;

	if ((lo >= 0) && (lo < 10)) {
		buf[0] = 0x30 + lo;
	}

	if ((lo > 9) && (lo < 16)) {
		buf[0] = 0x41 + lo -10;
	}

	if ((hi >= 0) && (hi < 10)) {
		buf[1] = 0x30 + hi;
	}

	if ((hi > 9) && (hi < 16)) {
		buf[1] = 0x41 + hi -10;
	}

	return buf;
}


char *bin_to_str(char *bin, int len)
{
	char *data;
	char *id_tmp;
	int i;

	data = (char*)malloc(len * 2 + 3);
	for (i = 0; i < len; i++) {
		id_tmp = (char*)char_bin_to_str(bin[i]);
		data[i*2] = id_tmp[1];
		data[i*2+1] = id_tmp[0];
		free(id_tmp);
	}
	data[i*2] = '\0';

	return data;
}

char *base64_decode(char * input, int length, int with_new_line)
{
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

void  MacToStr(char *str,unsigned char* mac)
{

	int i;
	char* ss=str;
	for(i=0;i<6;i++)
	{
		if((unsigned char)(mac[i] )< 16)
			sprintf(ss,"0%X",mac[i]);
		else
			sprintf(ss,"%X",mac[i]);
		ss+=2;

		if(i < 5)
		{
			*ss++='-';
		}
	}
}

char *mac2mac(char *mac)
{
	static char buf[24 + 1] = { 0 };
	int i;

	strncpy(buf, mac, 24);
	for (i = 0; i < strlen(buf); i++) {
		if (buf[i] == ':')
			buf[i] = '-';
	}
	return buf;
}

void str2mac(char *buf, unsigned char *mac_out)
{
	int mac[ETH_ALEN] = { 0, };
	char *mac_str;
	int i = 0;

	mac_str = mac2mac(buf);

	sscanf(mac_str, MAC_FORMAT_STRING, &mac[0], &mac[1], &mac[2], &mac[3],
	       &mac[4], &mac[5]);

	for (i = 0; mac_out && i < ETH_ALEN; i++)
		mac_out[i] = mac[i];
	return ;
}

void replace_mac(char* buf,char* out){
	int j = 0;

	for(int i = 0;i < strlen(buf);i++){
		if(buf[i] != '-'){
			out[j] = buf[i];
			j++;
		}
	}
	out[j] = '\0';
}
