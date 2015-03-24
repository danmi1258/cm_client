/*
 * http_client.cpp
 *
 *  Created on: Mar 9, 2015
 *      Author: root
 */

#include <uv.h>
#include "proc.h"
#include "client.h"
#include "http_parser.h"
#include <string>
#include <iostream>
#include <sstream>
#include "weixin_auth.h"
#include "igd/igd_lib.h"

using namespace std;

#define HTTP_SSERVER "183.57.39.193"
#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_err_name(err))

struct client_t {
	client_t() :
		body() {}
	http_parser parser;
	//int request_num;
	string request_;
	uv_tcp_t tcp;
	uv_connect_t connect_req;
	uv_shutdown_t shutdown_req;
	uv_write_t write_req;
	std::stringstream body;

	unsigned char mac[6];
	unsigned int ip;
	int if_index;
};

static http_parser_settings req_parser_settings;

int on_message_begin(http_parser* /*parser*/) {
  return 0;
}

int on_url(http_parser* /*parser*/, const char* at, size_t length) {
  return 0;
}

int on_header_field(http_parser* /*parser*/, const char* at, size_t length) {
  return 0;
}

int on_header_value(http_parser* /*parser*/, const char* at, size_t length) {
  return 0;
}

int on_headers_complete(http_parser* /*parser*/) {
  return 0;
}

int on_body(http_parser* parser, const char* at, size_t length) {

	client_t *client = (client_t*)parser->data;
	DEBUG_PRINT("on_body");
	if (at && client)
	{
		client->body << std::string(at,length);
		DEBUG_PRINT("body:%s\n",std::string(at,length).c_str());
		on_check_host_weixin_auth((char*)std::string(at,length).c_str(),(char*)client->mac,client->if_index,client->ip);
	}
	return 0;
}

void on_close(uv_handle_t* handle) {
  client_t* client = (client_t*) handle->data;
  DEBUG_PRINT("http on close\n");
  //client->tcp.data = NULL;
  delete client;
}

int on_message_complete(http_parser* parser) {

	client_t *client = (client_t*)parser->data;
	if (http_should_keep_alive(parser)){
		 uv_stream_t* tcp = (uv_stream_t*)&client->tcp;
		 uv_close((uv_handle_t*)tcp, on_close);
	}
	return 0;
}

void  http_client_init(){

	req_parser_settings.on_message_begin = on_message_begin;
	req_parser_settings.on_url = on_url;
	req_parser_settings.on_header_field = on_header_field;
	req_parser_settings.on_header_value = on_header_value;
	req_parser_settings.on_headers_complete = on_headers_complete;
	req_parser_settings.on_body = on_body;
	req_parser_settings.on_message_complete = on_message_complete;

}



void alloc_cb(uv_handle_t * /*handle*/, size_t suggested_size, uv_buf_t* buf) {
    *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
}

void after_write(uv_write_t* /*req*/, int status) {

}

void on_read_res(uv_stream_t *tcp, ssize_t nread, const uv_buf_t * buf) {

	ssize_t parsed;
	client_t* client = (client_t*) tcp->data;
	 if (nread > 0) {
		 DEBUG_PRINT("on_read_res %d\n",nread);
		 DEBUG_PRINT("%s\n",buf->base);
		 http_parser * parser = &client->parser;
		 parsed = (ssize_t)http_parser_execute(parser, &req_parser_settings, buf->base, nread);
		 if (parser->upgrade) {
			 DEBUG_PRINT("We do not support upgrades yet\n");
		 }else if(parsed != nread){
			 DEBUG_PRINT("parsed incomplete data: %ld/%ld bytes parsed\n", parsed, nread);
			 DEBUG_PRINT("\n*** %s ***\n",
					 http_errno_description(HTTP_PARSER_ERRNO(parser)));
		 }
	 }else{
		 if( nread == UV_EOF){
			 DEBUG_PRINT("on_read_res fail %d\n",nread);
		 }
		 /*UVERR(nread, "read");
		 if (nread != UV_EOF) {
			 UVERR(nread, "read");
		 }*/
	 }

	 free(buf->base);
}

void on_connect_http(uv_connect_t *req, int status) {

	client_t *client = (client_t*)req->handle->data;
	if (status == -1) {
		DEBUG_PRINT("connect failed error %s\n",uv_err_name(status));
		fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
		uv_close((uv_handle_t*)req->handle, on_close);
		return;
	}
	 DEBUG_PRINT("on_connect_http\n");
	 uv_buf_t resbuf;
	 resbuf.base = (char*)client->request_.c_str();
	 resbuf.len = client->request_.size();

	 uv_read_start(req->handle, alloc_cb, on_read_res);

	 uv_write(&client->write_req,
	            req->handle,
	            &resbuf,
	            1,
	            after_write);
}
void http_client_request(string& req,unsigned int ip,int if_index,unsigned char* mac){

	struct sockaddr_in dest;
	uv_ip4_addr(HTTP_SSERVER, 80, &dest);

	client_t* client = new client_t();
	client->request_ = req;
	memcpy(client->mac,mac,6);
	client->ip = ip;
	client->if_index = if_index;
	client->tcp.data = client;
	http_parser_init(&client->parser, HTTP_RESPONSE);
	http_client_init();
	client->parser.data = client;
	uv_tcp_init(loop, &client->tcp);
	uv_tcp_keepalive(&client->tcp,1,60);
	uv_tcp_connect(&client->connect_req, &client->tcp, (const struct sockaddr*)&dest, on_connect_http);
}
