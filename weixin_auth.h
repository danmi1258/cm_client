/*
 * weixin_auth.h
 *
 *  Created on: Mar 9, 2015
 *      Author: root
 */

#ifndef WEIXIN_AUTH_H_
#define WEIXIN_AUTH_H_

#include<vector>
#include<map>
#include<string>

using namespace std;

extern int weixin_auth_init(int  group);
extern bool  is_weixin_auth(int  group);
extern int destory_weixin_auth(int group);
extern void on_check_host_weixin_auth(char* body,char* mac,int if_index,unsigned int ip);
extern void check_host_weixin_auth(unsigned char* host_mac,unsigned int ip);
extern void add_weixin_auth(unsigned char* host_mac,unsigned int ip);

int add_skip_by_ip(int group,unsigned int ip);
int del_skip_by_ip(unsigned int ip);
struct host_cach_t{
	int old_time_couter;
	unsigned int ip;
};

extern map<string,host_cach_t> hostcach;

#endif /* WEIXIN_AUTH_H_ */
