/*
 * proc.cpp
 *
 *  Created on: Feb 12, 2015
 *      Author: root
 */
#include "proc.h"
#include "client.h"
#include "cJSON.h"
#include <fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
#include "igd/igd_lib.h"
#include "nc_ipc.h"
#include <openssl/sha.h>
#include "utile.h"
#include<string>
#include<vector>
#include<sstream>
#include "weixin_auth.h"

using namespace std;

#define MACLEN	6
#define MANAGVER "1.0.2"
#define NOS_HWID_LEN 16

#define GOOD_DEV_CHECK_DEFAULT 3
#define GOOD_DEV_CHECK 2
#define GOOD_DEV_DEVRND 1
#define GOOD_DEV 0
#define ERROR_DEV -1
#define ERROR_DEV_CHECK -2
#define ERROR_DEV_RE_REGISTER -3
#define ERROR_DEV_APP_TIMEOUT -4
#define ERROR_DEV_BREAK -5

#define WIFI_BLACK_MX 32


string strChallengeCode;
hertbit hb;
string strMagicNum="00000000000000000000000000000000";
//in other thread so async_client_write data  to main

uint64_t save_in_byte = 0;
uint64_t save_out_byte = 0;
void up_state_info(){

	DEBUG_PRINT("up_state_info\n");
	cJSON *json,*json_array,*fld;
	char *out;

	json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "RPCMethod", "info");

	double in_speed = 0;
	double out_speed = 0;
	struct if_stat stat;
	NOS_STRUCT_INIT(&stat);


	int r = get_if_stat("WAN1", &stat);
	DEBUG_PRINT("get_if_stat r=%d\n",r);
	DEBUG_PRINT("in speed %d\n",stat.in.speed);
	DEBUG_PRINT("out byte %lld\n",stat.out.byte);
	if( (save_in_byte == 0) && (save_out_byte == 0)){

		save_in_byte = stat.in.speed;
		save_out_byte = stat.out.byte;

		in_speed = 0;
		out_speed = 0;


	}else{
		in_speed = (double)((stat.in.byte - save_in_byte)/(1024*3600));
		out_speed = (double)((stat.out.byte - save_out_byte )/(1024*3600));
	}

	cJSON_AddNumberToObject(json,"Up",out_speed);
	cJSON_AddNumberToObject(json,"Down",in_speed);

	struct host_info info[HOST_MX] ;
	int i;
	int nr;
	memset(info, 0, sizeof(info));
	for (i=0;i<HOST_MX;i++)
		NOS_STRUCT_INIT(&info[i] );
	nr=dump_host_alive(info);
	cJSON_AddNumberToObject(json,"ClientNum",nr);

	int idx;
	struct wireless_site_survey site;
	wl_start_site_survey(0);
	sleep(7);

	json_array = cJSON_CreateArray();
	site.sizeOfStruct = sizeof(site);
	idx = 0;
	do{
		idx = wl_get_site(0, idx, &site);
		if(idx >= 0)
		{
			if(strlen((char*)site.ssid) != 0){
				cJSON_AddItemToArray(json_array,fld=cJSON_CreateObject());
				char site_mac[13];
				MacToStr(site_mac,site.bssid);
				cJSON_AddStringToObject(fld,"MAC",site_mac);
				cJSON_AddStringToObject(fld,"SSID",(char*)site.ssid);
				cJSON_AddNumberToObject(fld,"Strength",abs(site.rssi));
			}
		}
	}while(idx > 0);

	cJSON_AddItemToObject(json,"AroundWifi",json_array);

	DEBUG_PRINT("0000000000000\n");
	out = cJSON_Print(json);
	//DEBUG_PRINT("%s\n",out);
	printf("%s\n",out);
	c_state = c_up_stat_info;
	//client_write(out,strlen(out));
	DEBUG_PRINT("1111111111\n");
	async_client_write.data = (void*)out;
	DEBUG_PRINT("222222222\n");
	uv_async_send(&async_client_write);
	DEBUG_PRINT("3333333333\n");


	cJSON_Delete(json);
	//free(out);
}

bool b_get_param = false;
bool b_info_up_stat_info = false;

void igd_register(){

	save_in_byte = 0;
	save_out_byte = 0;

	b_get_param = false;
	b_info_up_stat_info = false;

	cJSON *json;
	char *out;
	char dev_sn_mac[20], buf_data[256];

	json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "RPCMethod", "Boot");

	struct nos_device_oem vendor;
	get_device_oem(&vendor);
	cJSON_AddStringToObject(json, "Vendor", "nowifi");

	get_igd_model_name(buf_data,256);
	cJSON_AddStringToObject(json, "Model", buf_data);

	get_device_version(buf_data,256);
	cJSON_AddStringToObject(json, "FirmwareVer", buf_data);

	cJSON_AddStringToObject(json, "HardwareVer", "5");
	cJSON_AddStringToObject(json,"ManagVer",MANAGVER);


	struct nos_wan_cfg wan_cfg;
	get_wan_config(&wan_cfg);
	cJSON_AddStringToObject(json, "IPAddr", inet_ntoa(wan_cfg.ip));

	struct nc_if *ifc;
	ifc = nc_uiname2if("LAN");
	MacToStr(dev_sn_mac,ifc->mac_clone);
	char str_dev_sn_mac[20] = {0};
	replace_mac(dev_sn_mac,str_dev_sn_mac);
	DEBUG_PRINT("lan mac:%s\n",str_dev_sn_mac);

	cJSON_AddStringToObject(json, "MAC", str_dev_sn_mac);

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);

	client_write(out,strlen(out));
	c_state = c_registe_first;

	cJSON_Delete(json);
	free(out);
	DEBUG_PRINT("igd_register finish");
}


void igd_register_second(){

	cJSON *json;
	char *out;
	char dev_sn_mac[20],hwid_buf[NOS_HWID_LEN];

	json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "RPCMethod", "Register");

	struct nc_if *ifc;
	ifc = nc_uiname2if("LAN");
	MacToStr(dev_sn_mac,ifc->mac_clone);
	char str_dev_sn_mac[20] = {0};
	replace_mac(dev_sn_mac,str_dev_sn_mac);
	DEBUG_PRINT("lan mac:%s\n",str_dev_sn_mac);
	cJSON_AddStringToObject(json, "MAC", str_dev_sn_mac);

	memset(hwid_buf, 0, NOS_HWID_LEN);
	get_device_hardware_id(hwid_buf);
	char* tmp,*tmp1,*checksn;
	tmp1 = bin_to_str(hwid_buf, NOS_HWID_LEN);
	DEBUG_PRINT("hwid:%s\n",tmp1);
	int len = strChallengeCode.size();
	checksn = (char*)malloc(len + strlen(tmp1) + 1);
	memcpy(checksn, strChallengeCode.c_str(), strChallengeCode.size());
	memcpy((unsigned char *)&checksn[len], tmp1, strlen(tmp1));
	SHA_CTX c;
	char m[SHA_DIGEST_LENGTH];
	if (!SHA1_Init(&c))
		return;
	SHA1_Update(&c,checksn,len+strlen(tmp1));
	SHA1_Final((unsigned char *)m,&c);
	free(checksn);
	tmp = bin_to_str(m, SHA_DIGEST_LENGTH);
	cJSON_AddStringToObject(json, "CheckHWID", tmp);
	free(tmp);
	free(tmp1);

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);

	client_write(out,strlen(out));
	c_state = c_registe_second;

	cJSON_Delete(json);
	free(out);
	DEBUG_PRINT("igd_register_second finish\n");
}

void Get_Param(){

	cJSON *json;
	char *out;

	DEBUG_PRINT("Get_Param");
	json = cJSON_CreateObject();

	cJSON_AddStringToObject(json, "RPCMethod", "getParameter");
	cJSON_AddNumberToObject(json,"ID",0);

	//char tmp[256];
	//get_config_path(sizeof(tmp),tmp);

	cJSON_AddStringToObject(json, "MagicNum", strMagicNum.c_str());

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);

	client_write(out,strlen(out));
	c_state = c_get_param;

	cJSON_Delete(json);
	free(out);
}

void info_client(struct nlk_host_msg *host){

	cJSON *json,*json_array,*fld;
	char *out;

	json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "RPCMethod", "clientAction");

	cJSON_AddNumberToObject(json, "ID",0);
	json_array = cJSON_CreateArray();

	struct host_info info;
	struct in_addr addr;
	NOS_STRUCT_INIT(&info);
	addr = host->addr;
	dump_host_info(addr, &info);

	cJSON_AddItemToArray(json_array,fld=cJSON_CreateObject());
	char host_mac[20];
	MacToStr(host_mac,(unsigned char*)host->mac);
	cJSON_AddStringToObject(fld,"MAC",host_mac);
	cJSON_AddNumberToObject(fld,"Time",time(NULL));
	if(host->comm.action == IGD_NLK_ADD){
		cJSON_AddStringToObject(fld,"Action","on");
		cJSON_AddNumberToObject(fld,"upFlow",0);
		cJSON_AddNumberToObject(fld,"downFlow",0);
		DEBUG_PRINT("IGD_NLK_ADD\n");
		check_host_weixin_auth((unsigned char*)host->mac,host->addr.s_addr);
	}else{
		cJSON_AddStringToObject(fld,"Action","off");
		cJSON_AddNumberToObject(fld,"upFlow",info.up_bytes/1000);
		cJSON_AddNumberToObject(fld,"downFlow",info.down_bytes/1000);

		map<string,host_cach_t>::iterator itr;
		itr = hostcach.find(string(host_mac));
		if( itr != hostcach.end()){
			del_skip_by_ip(host->addr.s_addr);
			hostcach.erase(itr);
			DEBUG_PRINT("host_cach erase %s\n",host_mac);
		}
	}

	cJSON_AddItemToObject(json,"Client",json_array);

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);

	client_write(out,strlen(out));
	c_state = c_info_client;
	cJSON_Delete(json);
	free(host);
	free(out);
}

void info_client_action_first(){

	cJSON *json,*json_array,*fld;

	char *out;
	json = cJSON_CreateObject();

	cJSON_AddStringToObject(json, "RPCMethod", "clientAction");
	cJSON_AddNumberToObject(json, "ID",0);
	json_array = cJSON_CreateArray();

	struct host_info info[HOST_MX] ;
	int nr;
	int i;
	memset(info, 0, sizeof(info));
	for (i=0;i<HOST_MX;i++)
		NOS_STRUCT_INIT(&info[i] );

	nr=dump_host_alive(info);
	for (i = 0; i < nr; i ++){
		cJSON_AddItemToArray(json_array,fld=cJSON_CreateObject());
		char host_mac[13];
		MacToStr(host_mac,info[i].mac);
		cJSON_AddStringToObject(fld,"MAC",host_mac);
		cJSON_AddNumberToObject(fld,"Time",time(NULL)-info[i].second);
		cJSON_AddStringToObject(fld,"Action","on");
		cJSON_AddNumberToObject(fld,"upFlow",info[i].up_bytes/1000);
		cJSON_AddNumberToObject(fld,"downFlow",info[i].down_bytes/1000);
	}

	cJSON_AddItemToObject(json,"Client",json_array);

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);

	client_write(out,strlen(out));
	c_state = c_info_client;

	cJSON_Delete(json);
	free(out);

}
void hert_check(int interval){

	cJSON *json;
	char dev_sn_mac[20];
	char *out;

	json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "RPCMethod", "Hb");

	struct nc_if *ifc;
	ifc = nc_uiname2if("LAN");
	MacToStr(dev_sn_mac,ifc->mac_clone);
	char str_dev_sn_mac[20] = {0};
	replace_mac(dev_sn_mac,str_dev_sn_mac);
	DEBUG_PRINT("lan mac:%s\n",str_dev_sn_mac);
	cJSON_AddStringToObject(json, "MAC", str_dev_sn_mac);

	out = cJSON_Print(json);
	DEBUG_PRINT("%s\n",out);


	hb.len = strlen(out);
	if( hb.p_buf != NULL){
		free(hb.p_buf);
		hb.p_buf = NULL;
	}
	hb.p_buf = out;
	hb.interval = interval;

	start_hert_check(&hb);
}

void proc_hert_check(int ret,cJSON *json){

	cJSON *json_tmp;

	switch (ret) {

	case ERROR_DEV_RE_REGISTER:
		DEBUG_PRINT("c_hert_check error -3\n");
		//lanuch_check_recv();
		re_register2();
		break;

	case ERROR_DEV_BREAK:
		DEBUG_PRINT("c_hert_check error -5\n");
		json_tmp = cJSON_GetObjectItem(json,"ServerIP");
		if (!json_tmp) {
			DEBUG_PRINT("cJSON_GetObjectItem ServerIP Error\n");
			return;
		}else{
			connect_server(json_tmp->valuestring);
		}
		break;

	case GOOD_DEV:
		json_tmp = cJSON_GetObjectItem(json,"Interval");
		if (json_tmp) {
			hb.interval = json_tmp->valueint;
		}
		break;

	default:
		DEBUG_PRINT("hert check invalid Result code\n");
		return;
	}
}

int interval;
void proc_reg_second(int ret,cJSON *json){

	cJSON *json_tmp;
	switch (ret) {

	case ERROR_DEV_CHECK:
		DEBUG_PRINT("c_registe_second error -2\n");
		re_register();
		break;

	case GOOD_DEV:
		json_tmp = cJSON_GetObjectItem(json,"Interval");
		if (json_tmp) {
			interval =  json_tmp->valueint;
			Get_Param();
		}
		break;
	default:
		DEBUG_PRINT("reg_second Invalid Result code\n");
		return;
	}
}
void proc_reg_first(int ret,cJSON *json){
	cJSON *json_tmp;
	switch (ret) {

	case ERROR_DEV:
		DEBUG_PRINT("c_registe_first error -1\n");
		lanuch_check_recv();
		break;

	case ERROR_DEV_BREAK:
		DEBUG_PRINT("c_registe_first error -5\n");
		json_tmp = cJSON_GetObjectItem(json,"ServerIP");
		if (!json_tmp) {
			DEBUG_PRINT("cJSON_GetObjectItem ServerIP Error\n");
			return;
		}else{
			connect_server(json_tmp->valuestring);
		}
		break;

	case GOOD_DEV:
		DEBUG_PRINT("c_registe_first ok\n");
		json_tmp = cJSON_GetObjectItem(json,"ChallengeCode");
		if (!json_tmp) {
			DEBUG_PRINT("cJSON_GetObjectItem ChallengeCode Error\n");
			return;
		}else{
			strChallengeCode = string(json_tmp->valuestring);
			//cJSON_Delete(json);
			igd_register_second();
		}
		break;

	default:
		DEBUG_PRINT("reg_first Invalid Result code\n");
		return;
	}
}

void get_acl_mac_array(char* s,vector<string>& macs){

	string strMacParam = string(s);
	istringstream iss(strMacParam);

	string line;
	while(std::getline(iss,line)){
		macs.push_back(line);
	}

}
int apply_cfg(char* param){

	cJSON *json,*json_tmp,*json_wifi;

	json = cJSON_Parse(param);

	//printf("param:%s\n",param);
	struct wireless_ap_cfg wifi_cfg_array[4];

	for(int i = 0;i < 4; i++){
		memset(&wifi_cfg_array[i],0,sizeof(wireless_ap_cfg));
		wifi_cfg_array[i].size_of_struct = sizeof(wireless_ap_cfg);
	}

	DEBUG_PRINT("aaaaaaaaaaa\n");
	int ifx, idx,i=0;
	struct wifi_if_ability *ifs;
	struct wifi_ability *abi;
	wl_abi_get(&abi);
	for(ifx = 0; ifx < abi ->if_sum; ifx++){
		ifs = &abi->ifs[ifx];
		for(idx = 0; idx < ifs->ext_sum; idx++){
			if( i < 4){
				wl_get_ssid(ifx,idx,&wifi_cfg_array[i]);
				i++;
			}
		}
	}
	DEBUG_PRINT("bbbbbbbbbbbbb\n");
	json_tmp = cJSON_GetObjectItem(json,"Private");
	json_wifi = cJSON_GetObjectItem(json_tmp,"radio");
	DEBUG_PRINT("ccccccccccc\n");
	int radio = json_wifi->valueint;
	json_wifi = cJSON_GetObjectItem(json_tmp,"redirect_url");
	str_redirect_url = string(json_wifi->valuestring);
	DEBUG_PRINT("redirect_url:%s\n",str_redirect_url.c_str());
	DEBUG_PRINT("i=%d\n",i);
	if( radio ==  1){
		for(int j = 0;j < i; j++){
			char wifi_idx[6] = {0};
			sprintf(wifi_idx,"wifi%d",j);
			DEBUG_PRINT("wifi_idx:%s\n",wifi_idx);
			json_tmp = cJSON_GetObjectItem(json,wifi_idx);
			json_wifi = cJSON_GetObjectItem(json_tmp,"ssid");
			DEBUG_PRINT("ssid:%s\n",json_wifi->valuestring);
			snprintf((char*)wifi_cfg_array[j].ssid,sizeof(wifi_cfg_array[j].ssid),"%s",json_wifi->valuestring);
			json_wifi = cJSON_GetObjectItem(json_tmp,"broad");
			wifi_cfg_array[j].broadcast_ssid = json_wifi->valueint;
			json_wifi = cJSON_GetObjectItem(json_tmp,"auth_type");
			DEBUG_PRINT("auth_type:%s\n",json_wifi->valuestring);
			if(strcmp(json_wifi->valuestring,"system") == 0){
				//if weixin quth  destory it
				switch(j){
				case 0:
					if( is_weixin_auth(UGRP_WIFI_1) ){
						destory_weixin_auth(UGRP_WIFI_1);
					}
					break;

				case 1:
					if( is_weixin_auth(UGRP_WIFI_2) ){
						destory_weixin_auth(UGRP_WIFI_2);
					}
					break;

				case 2:
					if( is_weixin_auth(UGRP_WIFI_3) ){
						destory_weixin_auth(UGRP_WIFI_3);
					}
					break;

				case 3:
					if( is_weixin_auth(UGRP_WIFI_4) ){
						destory_weixin_auth(UGRP_WIFI_4);
					}
					break;
				}
				json_wifi = cJSON_GetObjectItem(json_tmp,"sec_mode");
				int sec_mode = json_wifi->valueint;
				switch( sec_mode ){
				case 0:
					wifi_cfg_array[j].auth = W_AUTH_OPEN;
					break;
				case 1:
					wifi_cfg_array[j].auth = W_AUTH_WEPAUTO;
					break;
				case 2:
					break;
				case 3:
					wifi_cfg_array[j].auth = W_AUTH_WPA2PSK;
					break;
				case 4:
					wifi_cfg_array[j].auth = W_AUTH_WPA1PSKWPA2PSK;
					break;
				}

				if( sec_mode != 0){
					json_wifi = cJSON_GetObjectItem(json_tmp,"key_type");
					switch(json_wifi->valueint){
					case 1:
						wifi_cfg_array[j].encrypt = W_EN_TKIP;
						json_wifi = cJSON_GetObjectItem(json_tmp,"key");
						strncpy((char*)wifi_cfg_array[j].sec.wpa.key,json_wifi->valuestring,sizeof(wifi_cfg_array[j].sec.wpa.key));
						wifi_cfg_array[j].sec.wpa.rekey_time = 3600;
						break;

					case 2:
						wifi_cfg_array[j].encrypt = W_EN_WEP;
						json_wifi = cJSON_GetObjectItem(json_tmp,"key_mode");
						if( json_wifi->valueint == 1){
							wifi_cfg_array[j].sec.wep.key_mode = 1;
						}else{
							wifi_cfg_array[j].sec.wep.key_mode = 0;
						}
						json_wifi = cJSON_GetObjectItem(json_tmp,"key");
						wifi_cfg_array[j].sec.wep.key_default = 0;
						strncpy((char*)wifi_cfg_array[j].sec.wep.key[0],json_wifi->valuestring,sizeof(wifi_cfg_array[j].sec.wep.key));
						break;

					case 3:
						wifi_cfg_array[j].encrypt = W_EN_TKIPAES;
						json_wifi = cJSON_GetObjectItem(json_tmp,"key");
						strncpy((char*)wifi_cfg_array[j].sec.wpa.key,json_wifi->valuestring,sizeof(wifi_cfg_array[j].sec.wpa.key));
						wifi_cfg_array[j].sec.wpa.rekey_time = 3600;
						break;
					}
				}else{
					wifi_cfg_array[j].encrypt = W_EN_NONE;
				}
			}else if( strcmp(json_wifi->valuestring,"weixin") == 0 ){
				DEBUG_PRINT("weixin\n");
				int ret = 0;
				DEBUG_PRINT("j=%d\n",j);
				DEBUG_PRINT("%d  %d\n",wifi_cfg_array[j].auth,wifi_cfg_array[j].encrypt);
				wifi_cfg_array[j].auth = W_AUTH_OPEN; //weixin  NONE SYSTEM AUTH
				wifi_cfg_array[j].encrypt = W_EN_NONE;
				DEBUG_PRINT("None\n");
				switch(j){
				case 0:
					if( is_weixin_auth(UGRP_WIFI_1) == false)
						ret = weixin_auth_init(UGRP_WIFI_1);
					break;

				case 1:
					if( is_weixin_auth(UGRP_WIFI_2) == false)
						ret = weixin_auth_init(UGRP_WIFI_2);
					break;

				case 2:
					if( is_weixin_auth(UGRP_WIFI_3) == false)
						ret = weixin_auth_init(UGRP_WIFI_3);
					break;

				case 3:
					if( is_weixin_auth(UGRP_WIFI_4) == false)
						ret = weixin_auth_init(UGRP_WIFI_4);
					break;
				}

				DEBUG_PRINT("weixin_auth_init ret:%d\n",ret);
				if( ret < 0)
					return -1;
			}

			json_wifi = cJSON_GetObjectItem(json_tmp,"access_mode");
			if( json_wifi->valueint != 0){
				memset(wifi_cfg_array[j].list,0,sizeof(wifi_cfg_array[j].list));
				json_wifi = cJSON_GetObjectItem(json_tmp,"white_list");
				vector<string> black_mac;
				get_acl_mac_array(json_wifi->valuestring,black_mac);
				unsigned char mac_out[ETH_ALEN];
				wifi_cfg_array[j].host_acl_mode = json_wifi->valueint;
				for(size_t c = 0; c < black_mac.size();c++){
					str2mac((char*)black_mac[c].c_str(),mac_out);
					memcpy(wifi_cfg_array[j].list[c].mac,mac_out,ETH_ALEN);
					wifi_cfg_array[j].list[c].valid = 1;
				}
			}
		}

		i = 0;
		DEBUG_PRINT("333333333333\n");
		wl_abi_get(&abi);
		for(ifx = 0; ifx < abi ->if_sum; ifx++){
			ifs = &abi->ifs[ifx];
			for(idx = 0; idx < ifs->ext_sum; idx++){
				if( i < 4){
					DEBUG_PRINT("iiiiiiiiii%d %d %d\n",i,wifi_cfg_array[i].auth,wifi_cfg_array[i].encrypt);
					if( wl_set_ssid(ifx,idx,&wifi_cfg_array[i]) != 0){
						return -1;
					}
					i++;
				}
			}
		}
		DEBUG_PRINT("444444444\n");
		struct wifi_adv_cfg cfg;
		for(ifx = 0; ifx < abi ->if_sum; ifx++){
			memset(&cfg,0,sizeof(struct wifi_adv_cfg));
			cfg.size_of_struct = sizeof(struct wifi_adv_cfg);
			wl_adv_get(ifx,&cfg);
			json_tmp = cJSON_GetObjectItem(json,"Private");
			json_wifi = cJSON_GetObjectItem(json_tmp,"channel");
			cfg.chn =  json_wifi->valueint;
			json_wifi = cJSON_GetObjectItem(json_tmp,"wl_power");
			cfg.txPow = json_wifi->valueint;
			json_wifi = cJSON_GetObjectItem(json_tmp,"channel_width");
			if( json_wifi->valueint == 1){
				cfg.ht = WIFI_HT_20;
			}else if( json_wifi->valueint == 2){
				cfg.ht = WIFI_HT_40;
			}
			json_wifi = cJSON_GetObjectItem(json_tmp,"sl_stand");
			switch( json_wifi->valueint ){
			case 0:
				cfg.wifiMode = WIFI_MODE_11B;
				break;
			case 1:
				cfg.wifiMode = WIFI_MODE_11G ;
				break;
			case 2:
				cfg.wifiMode = WIFI_MODE_11N ;
				break;
			case 3:
				cfg.wifiMode = WIFI_MODE_11B|WIFI_MODE_11G ;
				break;
			case 4:
				cfg.wifiMode = WIFI_MODE_11G|WIFI_MODE_11N;
				break;
			case 5:
				cfg.wifiMode = WIFI_MODE_11B|WIFI_MODE_11G|WIFI_MODE_11N;
				break;
			}
			int ret;
			if( (ret  = wl_adv_set(ifx,&cfg)) != 0){
				DEBUG_PRINT("5555555555555%d\n",ret);
				return -1;
			}
		}
	}else{
		i = 0;
		wl_abi_get(&abi);
		for(ifx = 0; ifx < abi ->if_sum; ifx++){
			ifs = &abi->ifs[ifx];
			for(idx = 0; idx < ifs->ext_sum; idx++){
				if( i < 4){
					wifi_cfg_array[i].enable = 0;
					if( wl_set_ssid(ifx,idx,&wifi_cfg_array[i]) != 0){
						DEBUG_PRINT("666666666\n");
						return -1;
					}
					i++;
				}
			}
		}
	}

	json_wifi = cJSON_GetObjectItem(json_tmp,"lanip");
	DEBUG_PRINT("lanip:%s\n",json_wifi->valuestring);
	struct nos_lan_cfg lan;
	memset(&lan,0,sizeof(nos_lan_cfg));
	lan.size_of_struct = sizeof(nos_lan_cfg);
	get_lan_config(&lan);
	lan.ip.s_addr = inet_addr(json_wifi->valuestring);
	if( set_lan_config(&lan) != 0){
		DEBUG_PRINT("7777777\n");
		return -1;
	}
	return 0;
}

void proc_newparam(cJSON *json){

	cJSON *json_tmp,*json_re;
	char *out;
	json_tmp = cJSON_GetObjectItem(json,"ID");
	int id = json_tmp->valueint;

	json_tmp = cJSON_GetObjectItem(json,"Parameter");
	if( json_tmp != NULL){
		char* param = base64_decode(json_tmp->valuestring,strlen(json_tmp->valuestring),0);
		//DEBUG_PRINT("config param:%s\n",param);

		json_re = cJSON_CreateObject();
		if( apply_cfg(param) == 0){
			json_tmp = cJSON_GetObjectItem(json,"MagicNum");
			strMagicNum = string(json_tmp->valuestring);
			cJSON_AddNumberToObject(json_re, "Result", 0);
			DEBUG_PRINT("apply_cfg success\n");
		}
		else{
			cJSON_AddNumberToObject(json_re, "Result", -1);
			DEBUG_PRINT("apply_cfg fail\n");
		}
		cJSON_AddNumberToObject(json_re, "ID", id);
		out = cJSON_Print(json_re);

		DEBUG_PRINT("%s\n",out);
		client_write(out,strlen(out));
		cJSON_Delete(json_re);
		free(out);
	}
}

void proc_getParam(int ret,cJSON *json){
	switch (ret) {
	case 0:
		c_state = c_proc_param;
		proc_newparam(json);
		break;

	case -1:
		DEBUG_PRINT("param no change\n");
		DEBUG_PRINT("ffffffffffff\n");
		info_client_action_first();
		break;
	}
}

void proc_info_client_action(int ret,cJSON *json){

	switch (ret) {
	case -1:
		DEBUG_PRINT("info_client_action error -1\n");
		re_register();
		break;
	}

	if( ret != -1){
		if( b_info_up_stat_info == false){
			hert_check(interval);
			start_up_stat_info();
			b_info_up_stat_info = true;
		}
	}
}


void parse_json(char* buf,unsigned int len){

	cJSON *json,*json_tmp;

	DEBUG_PRINT("json return %s\n",buf);
	json = cJSON_Parse(buf);
	if (!json) {
		DEBUG_PRINT("cJSON_Parse Error\n");
		return;
	}
	else{
		json_tmp = cJSON_GetObjectItem(json,"Result");
		if (!json_tmp) {
			json_tmp = cJSON_GetObjectItem(json,"RPCMethod");
			if( json_tmp )
			{
				if( strcmp(json_tmp->valuestring,"newParameter") == 0){
					DEBUG_PRINT("newParameter\n");
					proc_newparam(json);
				}
			}else{
				DEBUG_PRINT("cJSON_GetObjectItem Result Error\n");
				cJSON_Delete(json);
				return;
			}
		}else{

			int ret = json_tmp->valueint;
			if( c_state == c_registe_first ){
				b_recv_suc = true;
				proc_reg_first(ret,json);
			}else if(c_state == c_registe_second){
				b_recv_suc = true;
				proc_reg_second(ret,json);
			}else if(c_state == c_hert_check){
				proc_hert_check(ret,json);
			}else if(c_state == c_get_param){
				b_recv_suc = true;
				proc_getParam(ret,json);
			}else if( c_state == c_info_client){
				b_recv_suc = true;
				proc_info_client_action(ret,json);
			}
		}
	}

	cJSON_Delete(json);
}

