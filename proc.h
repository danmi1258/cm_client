/*
 * proc.h
 *
 *  Created on: Feb 12, 2015
 *      Author: root
 */

#ifndef PROC_H_
#define PROC_H_

void igd_register();
void parse_json(char* buf,unsigned int len);
void info_client(struct nlk_host_msg *host);
void up_state_info();
void info_client_action_first();

typedef struct hertbit_s{
	char* p_buf;
	int len;
	int interval;
}hertbit;

extern hertbit hb;

#endif /* PROC_H_ */
