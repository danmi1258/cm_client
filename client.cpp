/*
 * client.cpp
 *
 *  Created on: Feb 10, 2015
 *      Author: hany
 */
#include <assert.h>
#include <norouter.h>


#include <unistd.h>
#include <vector>
#include <string>

#include "client.h"
#include "weixin_auth.h"
#include "utile.h"

using namespace std;

vector<string> server_ip;



#define SERVER_URL "www.163.com"
#define SERVER_PORT  1380
#define BUFFERSIZE  65536

uv_loop_t *loop;

uv_buf_t readbuffer_;//接受数据的buf
uv_buf_t writebuffer_;//写数据的buf

uv_write_t client_write_t;
uv_tcp_t client_sock;
uv_connect_t connect_t;
uv_getaddrinfo_t resolver;

//weixin auth
uv_getaddrinfo_t weixin_dns_t;
vector<string> v_weixin_ip;
int weixin_url_index = 0;
int weixin_url_num = 8;
char weixin_url[8][URL_NAME_LEN] = {"www.baidu.com","weixin.qq.com","long.weixin.qq.com",
		"short.weixin.qq.com","mmbiz.qpic.cn","wx.qlogo.cn","dns.weixin.qq.com","yesrouter.net"};
bool b_weixin_dns_suc = false;

struct addrinfo hints;


bool b_recv_suc = false;
unsigned char c_state;

unsigned int server_index = 0;

uv_timer_t timer_old;
uv_timer_t timer_reconnect;
uv_timer_t timer_check_recv;
uv_timer_t timer_re_register;
uv_timer_t timer_hert_check;
uv_timer_t timer_up_stat_info;
uv_timer_t timer_re_resolved;
uv_async_t async_info_client_action;
uv_async_t async_client_write;
uv_async_t async_register;
uv_async_t async_add_weixin_auth;

int check_recv_count = 0;
void on_connect(uv_connect_t* req, int status);
void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res);
void check_recv(uv_timer_t *handle);
void after_wirte(uv_write_t *req, int status);




void nlk_msg_thread(uv_work_t *req){

	struct igd_netlink_handler h;
	fd_set fds;
	int r,max_fd = 0;
	struct timeval tv;
	msg_app_t msg_start;
	struct nlk_sys_msg *sys_msg = NULL;

	nlk_msg_init(&h,(0x1 << (NLKMSG_GRP_STOP - 1))|
					(0x1 << (NLKMSG_GRP_HOST - 1))|
					(0x1 << (NLKMSG_GRP_IF - 1))|
					(0x1 << (NLKMSG_GRP_SYS - 1)) );

	while(1) {
		DEBUG_PRINT("999999999999999999999999999\n");
		FD_ZERO(&fds);
		IGD_FD_SET(h.sock_fd, &fds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		if ((r = select(max_fd+1, &fds, NULL, NULL, &tv)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
		}

		if (FD_ISSET(h.sock_fd,&fds)) {
			nlk_msg_recv(&h,&msg_start,sizeof(msg_app_t));
			DEBUG_PRINT("888888888888888888888888888%d\n",msg_start.comm.key);
			if(msg_start.comm.gid == NLKMSG_GRP_STOP){
				if( msg_start.comm.key == MSG_STOP){
					DEBUG_PRINT("---------------stop-----------\n");
					close(h.sock_fd);
					destory_weixin_auth(UGRP_WIFI_1);
					break;
				}
			}else if(msg_start.comm.gid == NLKMSG_GRP_HOST){
				struct nlk_host_msg *host;
				host = (struct nlk_host_msg*)malloc(sizeof(nlk_host_msg));
				//host = (struct nlk_host_msg *)&msg_start;
				memcpy(host,&msg_start,sizeof(nlk_host_msg));
				DEBUG_PRINT("host connect\n");
				async_info_client_action.data = (void*)host;
				uv_async_send(&async_info_client_action);
			}else if( msg_start.comm.gid == NLKMSG_GRP_IF){   //WAN IP Change
				if(msg_start.comm.key ==  IF_MSG_IP){
					struct nlk_if_msg* if_msg = (struct nlk_if_msg*)&msg_start;
					if( if_msg->type == IF_TYPE_WAN){
						uv_async_send(&async_register);
					}
				}
			}else if( msg_start.comm.gid == NLKMSG_GRP_SYS){
				sys_msg = (struct nlk_sys_msg *)&msg_start;
				DEBUG_PRINT("aaaaaaSYS_GRP_MID_ADVaaaaaa\n");
				if( sys_msg->comm.mid == SYS_GRP_MID_ADV){
					DEBUG_PRINT("SYS_GRP_MID_ADV\n");
					if( sys_msg->msg.adv.status == 200){
						DEBUG_PRINT("weixin auth status 200\n");
						struct sys_msg_adv* pAdv = (struct sys_msg_adv*)malloc(sizeof(struct sys_msg_adv));
						memcpy(pAdv,&sys_msg->msg.adv,sizeof(struct sys_msg_adv));
						async_add_weixin_auth.data = (void*)pAdv;
						uv_async_send(&async_add_weixin_auth);
					}else{
						DEBUG_PRINT("sys_msg->msg.adv.status error\n");
					}
				}
			}

		}
	}
}

void after_close_client_sock(uv_handle_t* handle){
	uv_timer_stop(&timer_hert_check);
	uv_timer_stop(&timer_up_stat_info);
}
void after_nlk_msg_thread_exit(uv_work_t *req, int status) {
	DEBUG_PRINT("0000000000000000000000nlk_msg_thread_exit\n");

	uv_close((uv_handle_t*)&client_sock,after_close_client_sock);
	uv_timer_stop(&timer_reconnect);
	uv_timer_stop(&timer_check_recv);
	uv_timer_stop(&timer_re_register);
	uv_timer_stop(&timer_re_resolved);
	uv_timer_stop(&timer_old);

	uv_close((uv_handle_t*)&weixin_dns_t,NULL);
	uv_close((uv_handle_t*)&resolver,NULL);
	uv_close((uv_handle_t*)&timer_reconnect,NULL);
	uv_close((uv_handle_t*)&timer_check_recv,NULL);
	uv_close((uv_handle_t*)&timer_re_register,NULL);
	uv_close((uv_handle_t*)&timer_hert_check,NULL);
	uv_close((uv_handle_t*)&timer_up_stat_info,NULL);
	uv_close((uv_handle_t*)&timer_re_resolved,NULL);
	uv_close((uv_handle_t*)&async_info_client_action,NULL);
	uv_close((uv_handle_t*)&async_client_write,NULL);
	uv_close((uv_handle_t*)&async_register,NULL);
	uv_close((uv_handle_t*)&async_add_weixin_auth,NULL);
	uv_close((uv_handle_t*)&timer_old,NULL);
	free(readbuffer_.base);
	free(writebuffer_.base);
	uv_stop(loop);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  //buf->base = (char*)malloc(suggested_size);
  //buf->len = suggested_size;
	*buf = readbuffer_;
}

void async_client_write_fun(uv_async_t *handle){

	char* p = (char*)handle->data;
	int len =  strlen(p);
	uint32_t i = htonl(len);
	memcpy(writebuffer_.base,&i,sizeof(uint32_t));
	char* ptr = writebuffer_.base;
	ptr = ptr + sizeof(uint32_t);
	memcpy(ptr,p,len);
	writebuffer_.len = len + sizeof(uint32_t);
	uv_write(&client_write_t,( uv_stream_t*)&client_sock,&writebuffer_,1,after_wirte);
	free(p);
}

void client_write(char* buf,int len){
	uint32_t i = htonl(len);
	memcpy(writebuffer_.base,&i,sizeof(uint32_t));
	char* ptr = writebuffer_.base;
	ptr = ptr + sizeof(uint32_t);
	memcpy(ptr,buf,len);
	writebuffer_.len = len + sizeof(uint32_t);
	uv_write(&client_write_t,( uv_stream_t*)&client_sock,&writebuffer_,1,after_wirte);
}

void re_resolved(uv_timer_t *handle){

	server_ip.clear();
	uv_getaddrinfo(loop, &resolver, on_resolved, SERVER_URL, "6667", &hints);
	uv_timer_stop(handle);
}

void after_wirte(uv_write_t *req, int status){

	if (status < 0) {
		fprintf(stderr, "Write error %s\n", uv_strerror(status));
		return;
	}

	if( c_state == c_registe_first  ){
		b_recv_suc = false;

		if( check_recv_count == 0){
			uv_timer_start(&timer_check_recv, check_recv, 10*1000, 0);
		}else{
			if( check_recv_count < 3){
				uv_timer_start(&timer_check_recv, check_recv, 60*1000, 0);
			}
			else{
				check_recv_count = 0;
				//uv_timer_stop(handle);
				uv_timer_start(&timer_re_resolved,re_resolved,4*60*1000,0);
			}
		}
	}else if( c_state == c_registe_second ){
		b_recv_suc = false;
		if( check_recv_count == 0){
			uv_timer_start(&timer_check_recv, check_recv, 30*1000, 0);
		}else{
			uv_timer_start(&timer_check_recv, check_recv, 180*1000, 0);
		}
	}
}

void lanuch_check_recv(){
	b_recv_suc = false;
	uv_timer_start(&timer_check_recv, check_recv, 0, 0);
}

void connect_server(char* server_addr){
	uv_close((uv_handle_t*)&client_sock,after_close_client_sock);
	uv_tcp_init(loop, &client_sock);
	struct sockaddr_in dest;
	uv_ip4_addr(server_addr, SERVER_PORT, &dest);
	uv_tcp_keepalive(&client_sock,1,60);
	uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
}

void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	DEBUG_PRINT("++++++on_read++++\n");

	if (nread < 0) {
		if (nread != UV_EOF){
			fprintf(stderr, "on_read Read error %s\n", uv_err_name(nread));
			uv_close((uv_handle_t*) &client_sock, after_close_client_sock);
			uv_tcp_init(loop, &client_sock);
			struct sockaddr_in dest;
			uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
			uv_tcp_keepalive(&client_sock,1,60);
			uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
			return;
		}
	}

	//b_recv_suc = true;
	check_recv_count = 0;

	unsigned int len = ntohl((unsigned int)buf->base);

	parse_json(buf->base+4,len);
}





void check_recv(uv_timer_t *handle){

	if( b_recv_suc == false){
		check_recv_count++;
		uv_close((uv_handle_t*)&client_sock,after_close_client_sock);
		uv_tcp_init(loop, &client_sock);
		struct sockaddr_in dest;
		server_index++;
		if( server_index >= server_ip.size() )
			server_index = 0;
		uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
		uv_tcp_keepalive(&client_sock,1,60);
		uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
		uv_timer_stop(handle);
	}
	else
	{
		check_recv_count = 0;
		uv_timer_stop(handle);
	}

}

void reconnect(uv_timer_t *handle) {
	uv_close((uv_handle_t*)&client_sock,after_close_client_sock);
	uv_tcp_init(loop, &client_sock);
	struct sockaddr_in dest;
	uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
	uv_tcp_keepalive(&client_sock,1,60);
	uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
	uv_timer_stop(handle);
}

void on_connect(uv_connect_t* req, int status){

	DEBUG_PRINT("++++++TCP Connect++++++++++++\n");
	if (status < 0) {
		fprintf(stderr, "on_connect callback callback error %s\n", uv_err_name(status));
		server_index++;
		if( server_index < server_ip.size() ){
			uv_timer_start(&timer_reconnect, reconnect, 60*1000, 0);
		}
		else{
			server_index = 0;
			uv_timer_start(&timer_reconnect, reconnect, 180*1000, 0);
		}
		return;
	}

	uv_read_start((uv_stream_t*) &client_sock, alloc_buffer, on_read);
	check_recv_count = 0;
	igd_register();
}

void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {

	DEBUG_PRINT("++++++++DNS Quering++++++++++\n");
	if (status < 0) {
		fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
		uv_getaddrinfo(loop, resolver, on_resolved, SERVER_URL, "6667", res);
		return;
	}

	struct addrinfo *cur;
	char addr[17] = {'\0'};
	for (cur = res; cur != NULL; cur = cur->ai_next) {
		uv_ip4_name((struct sockaddr_in*) cur->ai_addr, addr, 16);
		DEBUG_PRINT("%s\n",addr);
		server_ip.push_back(string(addr));
		printf("%s\n",addr);
	}

	struct sockaddr_in dest;
	server_index = 0;
	uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
	uv_tcp_keepalive(&client_sock,1,60);
	uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);

	uv_freeaddrinfo(res);
}


void re_register(){
	uv_timer_start(&timer_re_register, reconnect, 150*60*1000, 0); //150
}

void re_register2(){
	uv_timer_start(&timer_re_register, reconnect, 0, 0);
}

void async_re_register_fun(uv_async_t *handle){
	uv_timer_start(&timer_re_register, reconnect, 0, 0);
}
void after_up_state_inf_thread_exit(uv_work_t *req, int status){
	DEBUG_PRINT("+++++++++++++after_up_state_inf_thread_exit++++++++++++++\n");
}
void up_state_inf_thread(uv_work_t *req){
	up_state_info();
}

void fun_up_stat_info(uv_timer_t *handle){
	//up_state_info();
	uv_work_t req;
	req.data = NULL;
	uv_queue_work(loop,&req,up_state_inf_thread,after_up_state_inf_thread_exit);
}

void start_up_stat_info(){
	uv_timer_start(&timer_up_stat_info,fun_up_stat_info,0,60*60*1000);
}

void check_hert(uv_timer_t *handle) {
	hertbit* p = (hertbit*)handle->data;
	client_write(p->p_buf,p->len);
	c_state = c_hert_check;
	uv_timer_set_repeat(handle,p->interval*1000);
}

void start_hert_check(hertbit* pHB){
	timer_hert_check.data = (void*)pHB;
	uv_timer_start(&timer_hert_check, check_hert, 0, 0);
}

void async_info_client_action_fun(uv_async_t *handle){
	struct nlk_host_msg *host = (struct nlk_host_msg*)handle->data;
	info_client(host);
}

void old_timer_fun(uv_timer_t *handle){
	map<string,host_cach_t>::iterator itr;
	for(itr=hostcach.begin();itr != hostcach.end();){
		itr->second.old_time_couter = itr->second.old_time_couter - 1;
		if( itr->second.old_time_couter == 0){
			unsigned char mac[6];
			str2mac((char*)itr->first.c_str(),mac);
			check_host_weixin_auth(mac,itr->second.ip);
			//unregister_skip_mac(mac);
			//host_cach.erase(itr++);
		}
	}
}

void start_old_timer(){

	uv_timer_start(&timer_old,old_timer_fun,0,5*60*1000);
}

void async_add_weixin_auth_fun(uv_async_t *handle){

	struct sys_msg_adv* pAdv = (struct sys_msg_adv*)handle->data;
	add_weixin_auth(pAdv->host_mac,pAdv->host_ip);
	free(pAdv);
}

void on_weixin_dns(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res){

	DEBUG_PRINT("+++on_weixin_dns++++++++++\n");

	if (status < 0) {
		fprintf(stderr, "on_weixin_dns callback error %s\n", uv_err_name(status));
		uv_close((uv_handle_t*)&weixin_dns_t,NULL);
		b_weixin_dns_suc = false;
		v_weixin_ip.clear();
		weixin_url_index = 0;
		uv_getaddrinfo(loop, &weixin_dns_t, on_weixin_dns, weixin_url[weixin_url_index], "6667", &hints);
		return;
	}

	struct addrinfo *cur;
	char addr[17] = {'\0'};

	for (cur = res; cur != NULL; cur = cur->ai_next) {
		uv_ip4_name((struct sockaddr_in*) cur->ai_addr, addr, 16);
		DEBUG_PRINT("%s:%s\n",weixin_url[weixin_url_index],addr);
		v_weixin_ip.push_back(string(addr));
	}

	weixin_url_index++;
	if( weixin_url_index < weixin_url_num){
		uv_getaddrinfo(loop, &weixin_dns_t, on_weixin_dns, weixin_url[weixin_url_index], "6667", &hints);
	}else{
		b_weixin_dns_suc = true;
		weixin_auth_init(UGRP_WIFI_1);
	}

	uv_freeaddrinfo(res);
}
int main(void)
{

	loop = uv_default_loop();

	DEBUG_PRINT("+++++++++++++libuv++++++++++++++\n");
	nlk_start_msg(MSG_START_OK,NULL);

	uv_async_init(loop,&async_info_client_action,async_info_client_action_fun);
	uv_async_init(loop,&async_client_write,async_client_write_fun);
	uv_async_init(loop,&async_register,async_re_register_fun);
	uv_async_init(loop,&async_add_weixin_auth,async_add_weixin_auth_fun);

	uv_work_t req;
	req.data = NULL;
	uv_queue_work(loop,&req,nlk_msg_thread,after_nlk_msg_thread_exit);

	readbuffer_ =  uv_buf_init((char*) malloc(BUFFERSIZE), BUFFERSIZE);
	writebuffer_ = uv_buf_init((char*) malloc(BUFFERSIZE), BUFFERSIZE);


	uv_tcp_init(loop, &client_sock);
	uv_timer_init(loop, &timer_old);
	uv_timer_init(loop, &timer_reconnect);
	uv_timer_init(loop, &timer_hert_check);
	uv_timer_init(loop, &timer_up_stat_info);
	uv_timer_init(loop, &timer_re_register);
	uv_timer_init(loop, &timer_check_recv);
	uv_timer_init(loop, &timer_re_resolved);

	hb.p_buf = NULL;
	hb.len = 0;
	hb.interval = 0;

	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;


	b_weixin_dns_suc = false;
	weixin_url_index = 0;
	v_weixin_ip.clear();
	uv_getaddrinfo(loop, &weixin_dns_t, on_weixin_dns, weixin_url[weixin_url_index], "6667", &hints);
	//uv_getaddrinfo(loop, &resolver, on_resolved, SERVER_URL, "6667", &hints);

	uv_run(loop, UV_RUN_DEFAULT);
	DEBUG_PRINT("+++++++++++++Exit Loop++++++++++++++\n");
	uv_loop_close(loop);
	return 0;
}
