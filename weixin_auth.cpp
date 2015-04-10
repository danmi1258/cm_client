/*
 * weixin_auth.cpp
 *
 *  Created on: Mar 9, 2015
 *      Author: root
 */

#include "nc_ipc.h"
#include "client.h"
#include "weixin_auth.h"
#include "cJSON.h"
#include "utile.h"
#include "http_client.h"

#define URL_GROUP_MX 					20
#define DNS_GROUP_MX 					20
#define DNS_GROUP_NAME "mp_dns_group"


#define REDIRECT_URL "www.baidu.com"
#define IMAGE_URL "yesrouter.net/device_server/api/api_weixin.php"

struct kid_t{
	int webauth_kid;
	int param_kid;
	int url_group_id;
	int url_filter_id;
	vector<int> acl_pass_id;

};


map<int,kid_t> kid_map;
map<string,host_cach_t> hostcach;
map<unsigned int,int> ip_to_group;

bool  is_weixin_auth(int  group){

	map<int,kid_t>::iterator itr;
	itr = kid_map.find(group);

	if( itr != kid_map.end()){
		return true;
	}else{
		return false;
	}
}

int destory_weixin_auth(int group){

	int reg_webauth_kid = 0;
	int pa_id = 0;
	map<int,kid_t>::iterator itr;

	itr = kid_map.find(group);
	if( itr != kid_map.end()){
		DEBUG_PRINT("destory_weixin_auth %d\n",group);
		reg_webauth_kid = kid_map[group].webauth_kid;
		pa_id = kid_map[group].param_kid;
		unregister_group(GRP_URL, kid_map[group].url_group_id);
		unregister_http_ctrl(reg_webauth_kid);
		unregister_http_ctrl(pa_id);
		if( kid_map[group].url_filter_id >= 0){
			for(size_t i = 0; i < kid_map[group].acl_pass_id.size();i++){
				unregister_acl_filter(kid_map[group].acl_pass_id[i]);
			}
			unregister_url_filter(kid_map[group].url_filter_id);
		}
		kid_map.erase(itr);
	}
	else{
		return -1;
	}
	return 0;
}

int weixin_auth_init(int  group){
	user_group_mask_t ugrp = { 0,};
	struct inet_l3 l3;
	int reg_webauth_kid = 0;
	int ret = 0;
	struct in_addr addr;

	int urlid;
	int id;
	vector<int> v_ret;

	map<int,kid_t>::iterator itr;
	itr = kid_map.find(group);
	if( itr == kid_map.end()){

		igd_set_bit(group, ugrp);
		NOS_STRUCT_INIT(&l3);
		if( b_weixin_dns_suc == true){
			bool b_suc = true;
			for(size_t i = 0; i < v_weixin_ip.size();i++){
				inet_aton(v_weixin_ip[i].c_str(),&addr);
				l3.type = INET_L3_TYPE_STD;
				l3.addr.start = addr;
				l3.addr.end = addr;

				if( (ret = register_acl_filter(ugrp, ACTION_TYPE_PASS, &l3, NULL)) < 0){
					DEBUG_PRINT("register_acl_filter error %d\n",ret);
					b_suc = false;
					break;
				}else{
					DEBUG_PRINT("reg ip %s suc\n",v_weixin_ip[i].c_str());
					v_ret.push_back(ret);
				}
			}

			if( b_suc == false){
				DEBUG_PRINT("reg ip fail++++\n");
				for(size_t i = 0;i < v_ret.size();i++){
					unregister_acl_filter(v_ret[i]);
				}
				return -1;
			}

			char url_group_name[20];
			sprintf(url_group_name,"urlgroupname%d",group);
			urlid = register_url_group (url_group_name, 8, weixin_url);
			if( urlid < 0){
				DEBUG_PRINT("register_url_group error %d\n",urlid);
				for(size_t i = 0;i < v_ret.size();i++){
					unregister_acl_filter(v_ret[i]);
				}
				return -1;
			}
			id = register_url_filter_by_url_group(ugrp, 0, urlid);
			if( id >= 0){
				DEBUG_PRINT("register_url_filter_by_url_group suc\n");
			}
			else{
				DEBUG_PRINT("register_url_filter_by_url_group error %d\n",id);
				for(size_t i = 0;i < v_ret.size();i++){
					unregister_acl_filter(v_ret[i]);
				}
				unregister_group(GRP_URL, urlid);
				return -1;
			}
		}else{
			DEBUG_PRINT("b_weixin_dns_suc == false\n");
			return -1;
		}

		struct redirect_url rd;
		NOS_STRUCT_INIT(&rd);
		rd.islocal = 0;
		reg_webauth_kid = register_http_ctrl(ugrp,HTTP_CTRL_TYPE_WEBAUTH,NULL,REDIRECT_URL,&rd);
		if(reg_webauth_kid < 0){
			DEBUG_PRINT("register_http_ctrl error,%d\n",reg_webauth_kid);
			for(size_t i = 0;i < v_ret.size();i++){
				unregister_acl_filter(v_ret[i]);
			}
			unregister_group(GRP_URL, urlid);
			unregister_url_filter(id);
			return -1;
		}


		rd.send_msg = 1;
		igd_set_bit(URL_ARGS_PCMAC,rd.flags);
		int pa_id = register_http_ctrl(ugrp, HTTP_CTRL_TYPE_ADD_PARAMS, IMAGE_URL, NULL, &rd);
		if( pa_id < 0){
			DEBUG_PRINT("HTTP_CTRL_TYPE_ADD_PARAMS error,%d\n",pa_id);
			unregister_http_ctrl(reg_webauth_kid);
			for(size_t i = 0;i < v_ret.size();i++){
				unregister_acl_filter(v_ret[i]);
			}
			unregister_group(GRP_URL, urlid);
			unregister_url_filter(id);
			return -1;
		}
		kid_map[group].webauth_kid = reg_webauth_kid;
		kid_map[group].param_kid = pa_id;
		kid_map[group].url_group_id = urlid;
		kid_map[group].url_filter_id = id;
		kid_map[group].acl_pass_id.assign(v_ret.begin(),v_ret.end());
	}

	//start_old_timer();
	return 0;
}

int get_wl_mac(int c,char* mac){

	int ifx, idx,i=0;

	struct wifi_if_ability *ifs;
	struct wifi_ability *abi;
	wl_abi_get(&abi);

	struct wireless_ap_cfg cfg;
	for(ifx = 0; ifx < abi ->if_sum; ifx++){
		ifs = &abi->ifs[ifx];
		for(idx = 0; idx < ifs->ext_sum; idx++){
			if( i < 4){
				if( i == c){
					wl_get_ssid(ifx,idx,&cfg);
					memcpy(mac,cfg.mac,6);
					return 0;
				}
				i++;
			}
		}
	}
	return -1;
}

int get_if_index(char* host_mac){
	int ifx, idx,i=0,idx1 = 0;
	struct wifi_if_ability *ifs;
	struct wifi_ability *abi;

	wl_abi_get(&abi);
	struct WIFI_ASSOCIATED_STA sta;
	sta.sizeOfStruct = sizeof(sta);
	for(ifx = 0; ifx < abi ->if_sum; ifx++){
		ifs = &abi->ifs[ifx];
		for(idx = 0; idx < ifs->ext_sum; idx++){
			if( i < 4){
				idx1 = 0;
				do{
					idx1 = wl_get_associated_sta(ifx, idx, idx1, &sta);
					char site_mac[20];
					MacToStr(site_mac,(unsigned char*)sta.mac);
					DEBUG_PRINT("%s\n",site_mac);
					DEBUG_PRINT("next index:%d\n", idx1);
					if(idx1 >= 0)
					{
						if(memcmp(sta.mac,host_mac,6) == 0)
							return i;
					}
				}while(idx1 > 0);
				i++;
			}
		}
	}

	return -1;
}

int del_skip_by_ip(unsigned int ip){
	DEBUG_PRINT("del_skip_by_ip");
	int group;
	struct in_addr addr;
	addr.s_addr= ip;

	map<unsigned int,int>::iterator itr;
	itr = ip_to_group.find(ip);
	if( itr != ip_to_group.end()){
		group = itr->second;
		if( http_ctrl_action(addr,kid_map[group].webauth_kid,IGD_ACTION_DEL) < 0){
			DEBUG_PRINT("del_skip_by_ip webauth_kid error\n");
			return -1;
		}

		/*if( http_ctrl_action(addr,kid_map[group].param_kid,IGD_ACTION_DEL) < 0){
			DEBUG_PRINT("del_skip_by_ip param_kid error\n");
			return -1;
		}*/

		if( http_ctrl_action(addr,kid_map[group].url_filter_id,IGD_ACTION_DEL) < 0){
			DEBUG_PRINT("del_skip_by_ip url_filter_id error\n");
			return -1;
		}

		ip_to_group.erase(itr);
	}
	return 0;
}

int add_skip_by_ip(int group,unsigned int ip){

	DEBUG_PRINT("add_skip_by_ip");

	struct in_addr addr;
	addr.s_addr= ip;

	if( http_ctrl_action(addr,kid_map[group].webauth_kid,IGD_ACTION_ADD) < 0){
		DEBUG_PRINT("add_skip_by_ip webauth_kid error\n");
		return -1;
	}

	/*if( http_ctrl_action(addr,kid_map[group].param_kid,IGD_ACTION_ADD) < 0){
		DEBUG_PRINT("add_skip_by_ip param_kid error\n");
		return -1;
	}*/

	if( http_ctrl_action(addr,kid_map[group].url_filter_id,IGD_ACTION_ADD) < 0){
		DEBUG_PRINT("add_skip_by_ip url_filter_id error\n");
		return -1;
	}

	ip_to_group[ip] = group;
	return 0;
}

int get_group_by_ifidx(int if_idx){
	bool b_weixin_auth = false;
	int group;
	switch(if_idx){
	case 0:
		DEBUG_PRINT("UGRP_WIFI_1\n");
		group = UGRP_WIFI_1;
		b_weixin_auth = is_weixin_auth(UGRP_WIFI_1);
		break;

	case 1:
		DEBUG_PRINT("UGRP_WIFI_2\n");
		group = UGRP_WIFI_2;
		b_weixin_auth = is_weixin_auth(UGRP_WIFI_2);
		break;

	case 2:
		DEBUG_PRINT("UGRP_WIFI_3\n");
		group = UGRP_WIFI_3;
		b_weixin_auth = is_weixin_auth(UGRP_WIFI_3);
		break;

	case 3:
		DEBUG_PRINT("UGRP_WIFI_4\n");
		group = UGRP_WIFI_4;
		b_weixin_auth = is_weixin_auth(UGRP_WIFI_4);
		break;
	}

	if(b_weixin_auth){
		return group;
	}else{
		return -1;
	}
}

void on_check_host_weixin_auth(char* body,char* host_mac,int if_index,unsigned int ip){

	cJSON *json,*json_tmp;
	json = cJSON_Parse(body);
	DEBUG_PRINT("on_check_host_weixin_auth");
	DEBUG_PRINT("http body %s\n",body);
	char site_mac[20];
	MacToStr(site_mac,(unsigned char*)host_mac);
	map<string,host_cach_t>::iterator itr;
	itr = hostcach.find(string(site_mac));
	if( json != NULL){
		json_tmp = cJSON_GetObjectItem(json,"code");
		if( json_tmp->valueint == 200){
			DEBUG_PRINT("http 200\n");
			if( itr == hostcach.end()){
				int group = get_group_by_ifidx(if_index);
				if( add_skip_by_ip(group,ip) >= 0){
					host_cach_t ht;
					ht.old_time_couter = OLD_TIME_COUNT;
					ht.ip = ip;
					hostcach[string(site_mac)] = ht;
				}
			}else{
				itr->second.old_time_couter = OLD_TIME_COUNT;
			}
		}else if( json_tmp->valueint == 400){
			DEBUG_PRINT("on_check_host_weixin_auth http 400\n");
			if( itr != hostcach.end()){
				del_skip_by_ip(itr->second.ip);
				hostcach.erase(itr);
				DEBUG_PRINT("host_cach erase %s\n",host_mac);
			}
		}
	}
}


void add_weixin_auth(unsigned char* host_mac,unsigned int ip){

	map<string,host_cach_t>::iterator itr;
	char site_mac[20];
	MacToStr(site_mac,(unsigned char*)host_mac);
	DEBUG_PRINT("sta:%s\n",site_mac);
	itr = hostcach.find(string(site_mac));
	int if_idx = get_if_index((char*)host_mac);

	DEBUG_PRINT("if_idx %d\n",if_idx);
	int group;
	if( if_idx >= 0 ){
		if( (group = get_group_by_ifidx(if_idx)) >= 0){
			DEBUG_PRINT("b_weixin_auth true\n");
			if( itr == hostcach.end()){
				if( add_skip_by_ip(group,ip) >= 0){
					host_cach_t ht;
					ht.old_time_couter = OLD_TIME_COUNT;
					ht.ip = ip;
					hostcach[string(site_mac)] = ht;
				}
			}else{
				itr->second.old_time_couter = OLD_TIME_COUNT;
			}
		}else{
			DEBUG_PRINT("b_weixin_auth false\n");
		}
	}else{
		DEBUG_PRINT("if_idx < 0");
	}
}

void http_query_auth(unsigned char* host_mac,int if_idx,unsigned int ip){
	char dev_sn_mac[6];
	struct nos_lan_cfg lan;
	get_lan_config(&lan);
	get_ip_by_mac((unsigned char *)dev_sn_mac,&lan.ip);
	char str_dev_sn_mac[20];
	struct nc_if *ifc;
	ifc = nc_uiname2if("LAN");
	if( ifc != NULL){
		MacToStr(str_dev_sn_mac,ifc->mac_clone);
		DEBUG_PRINT("lan mac:%s\n",str_dev_sn_mac);
	}else{
		DEBUG_PRINT("ifc NULL\n");
		return;
	}


	char site_mac[20];
	MacToStr(site_mac,(unsigned char*)host_mac);

	char tmp_site_mac[20];
	char tmp_str_dev_sn_mac[20];

	replace_mac(site_mac,tmp_site_mac);
	replace_mac(str_dev_sn_mac,tmp_str_dev_sn_mac);

	char str_ssid_eth[2];
	sprintf(str_ssid_eth,"%d",if_idx);
	string params = "/device_server/api/api_weixin.php?action=againcheck&moble_mac="+
			string(tmp_site_mac)+"&router_mac="+string(tmp_str_dev_sn_mac)+"&ssid_eth="+string(str_ssid_eth)+" HTTP/1.1\r\n";

	string http_request = "GET "+ params +
			"Host: yesrouter.net\r\n"
			"User-Agent: webclient.c\r\n"
			"Keep-Alive: 100\r\n"
			"Connection: keep-alive\r\n"
			"\r\n";

	DEBUG_PRINT("http query\n");
	DEBUG_PRINT("%s\n",http_request.c_str());
	http_client_request(http_request,ip,if_idx,host_mac);
}

void check_host_weixin_auth(unsigned char* host_mac,unsigned int ip){
	map<string,host_cach_t>::iterator itr;
	char site_mac[20];
	MacToStr(site_mac,(unsigned char*)host_mac);

	itr = hostcach.find(string(site_mac));
	int if_idx = get_if_index((char*)host_mac);

	DEBUG_PRINT("check_host_weixin_auth\n");
	DEBUG_PRINT("if_idx %d\n",if_idx);
	int group;
	if( if_idx >= 0){
		if( (group = get_group_by_ifidx(if_idx)) >= 0){
			if( itr != hostcach.end()){
				DEBUG_PRINT("host_cach have host\n");
				itr->second.old_time_couter = OLD_TIME_COUNT;
			}else{
				DEBUG_PRINT("http_query_auth\n");
				http_query_auth(host_mac,if_idx,ip);
			}
		}
	}
}
