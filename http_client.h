/*
 * http_client.h
 *
 *  Created on: Mar 10, 2015
 *      Author: root
 */

#ifndef HTTP_CLIENT_H_
#define HTTP_CLIENT_H_
#include<string>
using namespace std;

extern void http_client_request(string& req,unsigned int ip,int if_index,unsigned char* mac);

#endif /* HTTP_CLIENT_H_ */
