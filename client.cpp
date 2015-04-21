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

uv_write_t *client_write_t;
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


uv_timer_t timer_check_connect;
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
void check_connect_timer_fun(uv_timer_t *handle);
void reconnect(uv_timer_t *handle);


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
			DEBUG_PRINT("888888888888888888888888888%d\n",msg_start.comm.gid);
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
					DEBUG_PRINT("IF_MSG_IP\n");
					struct nlk_if_msg* if_msg = (struct nlk_if_msg*)&msg_start;
					if( (if_msg->type == IF_TYPE_WAN) && (if_msg->offline == false)){
						DEBUG_PRINT("IF_TYPE_WAN\n");
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
	DEBUG_PRINT("after_close_client_sock 1111\n");
	uv_timer_stop(&timer_hert_check);
	uv_timer_stop(&timer_up_stat_info);
	DEBUG_PRINT("after_close_client_sock 22222\n");
}
void after_nlk_msg_thread_exit(uv_work_t *req, int status) {
	DEBUG_PRINT("0000000000000000000000nlk_msg_thread_exit\n");

	uv_close((uv_handle_t*)&client_sock,after_close_client_sock);
	uv_timer_stop(&timer_reconnect);
	uv_timer_stop(&timer_check_recv);
	uv_timer_stop(&timer_re_register);
	uv_timer_stop(&timer_re_resolved);
	uv_timer_stop(&timer_old);
	uv_timer_stop(&timer_check_connect);

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
	uv_close((uv_handle_t*)&timer_check_connect,NULL);
	free(readbuffer_.base);
	free(writebuffer_.base);
	uv_stop(loop);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  //buf->base = (char*)malloc(suggested_size);
  //buf->len = suggested_size;
	DEBUG_PRINT("alloc_buffer\n");
	memset(readbuffer_.base,0,readbuffer_.len);
	*buf = readbuffer_;
}

void async_client_write_fun(uv_async_t *handle){

	DEBUG_PRINT("async_client_write_fun\n");
	memset((void*)writebuffer_.base,0,writebuffer_.len);
	char* p = (char*)handle->data;
	int len =  strlen(p);
	uint32_t i = htonl(len);
	memcpy(writebuffer_.base,&i,sizeof(uint32_t));
	char* ptr = writebuffer_.base;
	ptr = ptr + sizeof(uint32_t);
	memcpy(ptr,p,len);
	writebuffer_.len = len + sizeof(uint32_t);
	client_write_t =  (uv_write_t*)malloc(sizeof(uv_write_t));
	uv_write(client_write_t,( uv_stream_t*)&client_sock,&writebuffer_,1,after_wirte);
	free(p);
	DEBUG_PRINT("async_client_write_fun end\n");
}

void client_write(char* buf,int len){
	memset((void*)writebuffer_.base,0,writebuffer_.len);
	uint32_t i = htonl(len);
	memcpy(writebuffer_.base,&i,sizeof(uint32_t));
	char* ptr = writebuffer_.base;
	ptr = ptr + sizeof(uint32_t);
	memcpy(ptr,buf,len);
	writebuffer_.len = len + sizeof(uint32_t);
	DEBUG_PRINT("client_write%s+++%d\n",writebuffer_.base+sizeof(uint32_t),writebuffer_.len);
	client_write_t =  (uv_write_t*)malloc(sizeof(uv_write_t));
	int r  = uv_write(client_write_t,( uv_stream_t*)&client_sock,&writebuffer_,1,after_wirte);
	if( r < 0){
		DEBUG_PRINT("Write error %s\n",uv_strerror(r));
	}
	DEBUG_PRINT("client_write finished\n");
}

void re_resolved(uv_timer_t *handle){

	server_ip.clear();
	uv_getaddrinfo(loop, &resolver, on_resolved, SERVER_URL, "6667", &hints);
	uv_timer_stop(handle);
}

void after_wirte(uv_write_t *req, int status){

	DEBUG_PRINT("after_wirte\n");
	if (status < 0) {
		uv_timer_stop(&timer_check_connect);
		DEBUG_PRINT("Write error %s\n",uv_strerror(status));
		uv_timer_start(&timer_reconnect, reconnect, 0, 0);
		free(req);
		return;
	}

	if( c_state == c_registe_first  ){
		b_recv_suc = false;

		if( check_recv_count == 0){
			DEBUG_PRINT("check_recv_count == 0\n");
			uv_timer_start(&timer_check_recv, check_recv, 10*1000, 0);
			DEBUG_PRINT("111111111111111\n");
		}else{
			if( check_recv_count < 3){
				DEBUG_PRINT("check_recv_count < 3\n");
				uv_timer_start(&timer_check_recv, check_recv, 60*1000, 0);
			}
			else{
				DEBUG_PRINT("check_recv_count > 3\n");
				check_recv_count = 0;
				uv_timer_start(&timer_re_resolved,re_resolved,4*60*1000,0);
			}
		}
	}else if( (c_state == c_registe_second) || (c_state == c_get_param) || (c_state == c_info_client)){
		b_recv_suc = false;
		if( check_recv_count == 0){
			DEBUG_PRINT("c_registe_second check_recv_count == 0\n");
			uv_timer_start(&timer_check_recv, check_recv, 30*1000, 0);
		}else{
			DEBUG_PRINT("c_registe_second check_recv_count != 0\n");
			uv_timer_start(&timer_check_recv, check_recv, 180*1000, 0);
		}
	}else if( c_state == c_proc_param ){
		DEBUG_PRINT("ffffffffffff\n");
		info_client_action_first();
	}
	free(req);
	DEBUG_PRINT("22222222222222\n");
}

void lanuch_check_recv(){
	b_recv_suc = false;
	uv_timer_start(&timer_check_recv, check_recv, 0, 0);
}

void connect_server(char* server_addr){
	uv_read_stop((uv_stream_t*) &client_sock);
	uv_timer_stop(&timer_hert_check);
	uv_timer_stop(&timer_up_stat_info);
	uv_tcp_init(loop, &client_sock);
	struct sockaddr_in dest;
	uv_ip4_addr(server_addr, SERVER_PORT, &dest);
	uv_tcp_keepalive(&client_sock,1,60);
	uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
	uv_timer_start(&timer_check_connect, check_connect_timer_fun, 15*1000, 0);
}

void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	DEBUG_PRINT("++++++on_read++++\n");

	if (nread < 0) {
		if (nread != UV_EOF){
			fprintf(stderr, "on_read Read error %s\n", uv_err_name(nread));
			uv_read_stop((uv_stream_t*) &client_sock);
			uv_timer_stop(&timer_hert_check);
			uv_timer_stop(&timer_up_stat_info);
			uv_tcp_init(loop, &client_sock);
			struct sockaddr_in dest;
			uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
			uv_tcp_keepalive(&client_sock,1,60);
			uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
			uv_timer_start(&timer_check_connect, check_connect_timer_fun, 15*1000, 0);
			return;
		}
	}

	if( (c_state == c_registe_first) || ( c_state == c_registe_second ) ||
			(c_state == c_get_param) || (c_state == c_info_client) ){
		uv_timer_stop(&timer_check_recv);
		check_recv_count = 0;
	}
	check_recv_count = 0;

	unsigned int len = ntohl((unsigned int)buf->base);

	parse_json(buf->base+4,len);
}





void check_recv(uv_timer_t *handle){

	DEBUG_PRINT("check_recv\n");
	if( b_recv_suc == false){
		DEBUG_PRINT("b_recv_suc false\n");
		check_recv_count++;
		uv_read_stop((uv_stream_t*) &client_sock);
		uv_timer_stop(&timer_hert_check);
		uv_timer_stop(&timer_up_stat_info);
		DEBUG_PRINT("a\n");
		int re = uv_tcp_init(loop, &client_sock);
		if( re < 0){
			DEBUG_PRINT("uv_tcp_init error %s\n",uv_err_name(re));
		}
		DEBUG_PRINT("b\n");
		struct sockaddr_in dest;
		server_index++;
		if( server_index >= server_ip.size() )
			server_index = 0;
		DEBUG_PRINT("server:%s\n",server_ip[server_index].c_str());
		uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
		uv_tcp_keepalive(&client_sock,1,60);
		int r = uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
		uv_timer_start(&timer_check_connect, check_connect_timer_fun, 15*1000, 0);
		if( r < 0){
			DEBUG_PRINT("uv_tcp_connect error %s\n",uv_err_name(r));
		}
		uv_timer_stop(handle);
		DEBUG_PRINT("v\n");
	}
	else
	{
		check_recv_count = 0;
		uv_timer_stop(handle);
	}

}



void reconnect(uv_timer_t *handle) {
	DEBUG_PRINT("reconnect");
	uv_read_stop((uv_stream_t*) &client_sock);
	uv_timer_stop(&timer_hert_check);
	uv_timer_stop(&timer_up_stat_info);
	uv_tcp_init(loop, &client_sock);
	struct sockaddr_in dest;
	uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
	uv_tcp_keepalive(&client_sock,1,60);
	uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
	uv_timer_start(&timer_check_connect, check_connect_timer_fun, 15*1000, 0);
	uv_timer_stop(handle);
}


void check_connect_timer_fun(uv_timer_t *handle){

	DEBUG_PRINT("check_connect_timer_fun\n");
	uv_timer_start(&timer_reconnect, reconnect, 0, 0);
	uv_timer_stop(handle);
}

void on_connect(uv_connect_t* req, int status){

	DEBUG_PRINT("++++++TCP Connect++++++++++++\n");
	uv_timer_stop(&timer_check_connect);
	if (status < 0) {
		//fprintf(stderr, "on_connect callback callback error %s\n", uv_err_name(status));
		DEBUG_PRINT("on_connect callback callback error %s\n",uv_err_name(status));
		server_index++;
		if( server_index < server_ip.size() ){
			uv_timer_start(&timer_reconnect, reconnect, 60*1000, 0);
		}
		else{
			DEBUG_PRINT("reconnect 180*1000\n");
			server_index = 0;
			uv_timer_start(&timer_reconnect, reconnect, 180*1000, 0);
		}
		return;
	}

	uv_read_start((uv_stream_t*) &client_sock, alloc_buffer, on_read);

	igd_register();
}

void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {

	DEBUG_PRINT("++++++++DNS Quering++++++++++\n");
	if (status < 0) {
		//uv_close((uv_handle_t*)&resolver,NULL);
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
	DEBUG_PRINT("re_register\n");
	uv_timer_stop(&timer_check_connect);
	uv_timer_start(&timer_re_register, reconnect, 150*60*1000, 0); //150
}

void re_register2(){
	uv_timer_stop(&timer_check_connect);
	uv_timer_start(&timer_re_register, reconnect, 0, 0);
}

void async_re_register_fun(uv_async_t *handle){
	DEBUG_PRINT("async_re_register_fun\n");
	uv_timer_stop(&timer_check_connect);
	uv_timer_start(&timer_re_register, reconnect, 15*1000, 0);
}
void after_up_state_inf_thread_exit(uv_work_t *req, int status){
	DEBUG_PRINT("+++++++++++++after_up_state_inf_thread_exit++++++++++++++\n");
}
void up_state_inf_thread(uv_work_t *req){
	up_state_info();
}

uv_work_t req1;
void fun_up_stat_info(uv_timer_t *handle){
	//up_state_info();
	DEBUG_PRINT("fun_up_stat_info\n");

	req1.data = NULL;
	int r  = uv_queue_work(loop,&req1,up_state_inf_thread,after_up_state_inf_thread_exit);
	if( r < 0){
		DEBUG_PRINT("uv_queue_work error %d\n",r);
	}
}

void start_up_stat_info(){
	DEBUG_PRINT("start_up_stat_info\n");
	uv_timer_start(&timer_up_stat_info,fun_up_stat_info,0,60*60*1000);
}

void check_hert(uv_timer_t *handle) {

	DEBUG_PRINT("check_hert\n");
	hertbit* p = (hertbit*)handle->data;
	c_state = c_hert_check;
	client_write(p->p_buf,p->len);
	uv_timer_set_repeat(handle,p->interval*1000);
}

void start_hert_check(hertbit* pHB){
	DEBUG_PRINT("start_hert_check\n");
	timer_hert_check.data = (void*)pHB;
	uv_timer_start(&timer_hert_check, check_hert, 0, pHB->interval*1000);
}

void async_info_client_action_fun(uv_async_t *handle){
	struct nlk_host_msg *host = (struct nlk_host_msg*)handle->data;
	info_client(host);
}

void old_timer_fun(uv_timer_t *handle){
	DEBUG_PRINT("old_timer_fun\n");
	map<string,host_cach_t>::iterator itr;
	for(itr=hostcach.begin();itr != hostcach.end();){
		itr->second.old_time_couter = itr->second.old_time_couter - 1;
		if( itr->second.old_time_couter == 0){
			unsigned char mac[6];
			str2mac((char*)itr->first.c_str(),mac);
			int if_idx = get_if_index((char*)mac);
			if( if_idx >= 0){
				DEBUG_PRINT("old_timer_fun %s\n",itr->first.c_str());
				http_query_auth(mac,if_idx,itr->second.ip);
			}
		}
		itr++;
	}
}

void start_old_timer(){

	uv_timer_start(&timer_old,old_timer_fun,OLD_TIME_REPEAT,OLD_TIME_REPEAT);
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
		//uv_close((uv_handle_t*)&weixin_dns_t,NULL);
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
		//weixin_auth_init(UGRP_WIFI_1);
		server_ip.push_back(string("172.16.117.100"));
		struct sockaddr_in dest;
		server_index = 0;
		uv_ip4_addr(server_ip[server_index].c_str(), SERVER_PORT, &dest);
		uv_tcp_keepalive(&client_sock,1,60);
		uv_tcp_connect(&connect_t, &client_sock, (const struct sockaddr*)&dest, on_connect);
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
	uv_timer_init(loop,&timer_check_connect);

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
