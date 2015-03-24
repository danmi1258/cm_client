/*
 * utile.h
 *
 *  Created on: Feb 25, 2015
 *      Author: root
 */

#ifndef UTILE_H_
#define UTILE_H_


char *bin_to_str(char *bin, int len);
char *base64_decode(char * input, int length, int with_new_line);
void  MacToStr(char *str,unsigned char* mac);
void str2mac(char *buf, unsigned char *mac_out);
void replace_mac(char* buf,char* out);

#endif /* UTILE_H_ */
