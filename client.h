/*
 * client.h
 *
 *  Created on: Feb 12, 2015
 *      Author: root
 */

#ifndef CLIENT_H_
#define CLIENT_H_

#include <uv.h>
#include "proc.h"
#include<vector>
#include<string>

using namespace std;

#if 1
#define DEBUG_PRINT(fmt,args...)    console_printf("%s: line = %d "fmt,__FUNCTION__, __LINE__, ##args)
#else
#define DEBUG_PRINT(fmt,args...)    do{}while(0)
#endif


enum client_state{
	c_registe_first,
	c_registe_second,
	c_hert_check,
	c_get_param,
	c_info_client,
	c_up_stat_info
};

extern bool b_recv_suc;
extern unsigned char c_state;
extern uv_async_t async_client_write;
extern uv_loop_t *loop;

extern vector<string> v_weixin_ip;
extern bool b_weixin_dns_suc;
extern char weixin_url[8][64];

void client_write(char* buf,int len);
void lanuch_check_recv();
void connect_server(char* server_addr);
void re_register();
void re_register2();
void start_hert_check(hertbit* pHB);
void start_up_stat_info();
void start_old_timer();

#endif /* CLIENT_H_ */
