%token INTEGER AUTH_PWD KW_INTERFACE KW_VROUTER KW_ADVERINT KW_PRIORITY KW_PREEMPT KW_IPLIST KW_AUTH BRA KET EOS

%{
#include "vrrpd.h"
  uint32_t p_src_ip;
  vrid_node_t * p_cur_vrid_node, * p_prev_vrid_node = NULL, * p_head_node = NULL;
  vrrp_instance * p_cur_vrrp_inst;
  timespec_t p_ai_ts;
  uchar_t p_priority = VRRP_DEFAULT_PRIORITY;
  uchar_t p_preempt = VRRP_DEFAULT_PREEMPT;
  uchar_t p_adverint = VRRP_DEFAULT_ADVERINT;
  uchar_t p_auth_type = AUTH_NONE;
  uchar_t p_ip_count = 0;
  uint32_t p_addresses[255];
  uint32_t p_auth_data[AUTH_DATA_SIZE];
  if_config_t * p_cur_if_conf;
  ifconf_node_t * p_cur_ifconf_node;
  ifconf_node_t * p_prev_ifconf_node = NULL;
  ifconf_node_t * p_head_ifconf_node = NULL;
  int ifcount;
  int log_level = LOG_LEV2;
  %}


%%

config:
interfaces
;

interfaces:
interface
| interfaces interface
;

interface:
KW_INTERFACE INTEGER BRA if_options KET EOS
{
  //printf("parser: found interface statment\n"); 
  p_cur_if_conf = create_if_config( p_auth_type, p_auth_data, $2);
  p_cur_vrid_node = p_head_node;
  p_cur_if_conf->head_node = p_head_node;
  while(p_cur_vrid_node != NULL)
    {
      p_cur_vrid_node->vrrp_inst_ptr->haddr = p_cur_if_conf->haddr;
      p_cur_vrid_node->vrrp_inst_ptr->pkt->src_ip = p_cur_if_conf->src_ip;
      p_cur_vrid_node->vrrp_inst_ptr->pkt->auth_type = p_cur_if_conf->auth_type;
      p_ip_count = p_cur_vrid_node->vrrp_inst_ptr->pkt->ip_count;
      memcpy(&p_cur_vrid_node->vrrp_inst_ptr->pkt->dyndata[p_ip_count],
	     p_auth_data, AUTH_PWD_BUF);
      p_cur_vrid_node->vrrp_inst_ptr->pkt->checksum =
	vrrp_checksum(p_cur_vrid_node->vrrp_inst_ptr->pkt); 
      p_cur_vrid_node = p_cur_vrid_node->next_node_ptr;		
    }
  p_cur_ifconf_node = create_ifconf_node( p_cur_if_conf, p_prev_ifconf_node);
  p_prev_ifconf_node = p_cur_ifconf_node;
  if (p_head_ifconf_node == NULL)
    p_head_ifconf_node = p_cur_ifconf_node;
  ifcount++;

  // re-init vrrp_inst nodes for next i/f
  p_prev_vrid_node = NULL;
  p_head_node = NULL;
  p_ip_count = 0;
}
;

if_options:
if_option
| if_options if_option
;

if_option:
KW_AUTH INTEGER EOS
| KW_AUTH INTEGER AUTH_PWD EOS
{
  //printf("passwd: %s\n", l_strbuf);
  memcpy(p_auth_data, l_strbuf, AUTH_PWD_BUF); 
  p_auth_type = $2;
}
| vrouters
;

vrouters:
vrouter
| vrouters vrouter
;

vrouter:
KW_VROUTER INTEGER BRA vrouter_options KET EOS
{
  //printf("parser: vrouter: %i\n", $2); 
  p_ai_ts.tv_sec = p_adverint;
  p_ai_ts.tv_nsec = 0;
  p_cur_vrrp_inst = create_vrrp_instance( $2, p_priority, p_ai_ts, p_preempt, p_ip_count, p_addresses);
  p_cur_vrid_node = create_vrid_node( p_cur_vrrp_inst, p_prev_vrid_node );
  if (p_head_node == NULL)
    p_head_node = p_cur_vrid_node;
  p_prev_vrid_node = p_cur_vrid_node;

  // Reset values for next vrouter
  p_priority = VRRP_DEFAULT_PRIORITY;
  p_preempt = VRRP_DEFAULT_PREEMPT;
  p_adverint = VRRP_DEFAULT_ADVERINT;
  p_ip_count = 0;
					
			
}
;

vrouter_options:
vrouter_option
| vrouter_options vrouter_option
;

vrouter_option:
KW_PRIORITY INTEGER EOS
{
  //printf("parser: priority: %i\n", $2); 
  p_priority = $2;
}
| KW_PREEMPT INTEGER EOS
{
  //printf("parser: preempt: %i\n", $2); 
  p_preempt = $2;
}
| KW_ADVERINT INTEGER EOS
{
  //printf("parser: adver int: %i\n", $2);
  p_adverint = $2;
}
| KW_IPLIST BRA ip_list KET EOS
{
  //printf("parser: ip list created\n");
}
;

ip_list:
ip_addr
| ip_list ip_addr
;

ip_addr:
INTEGER EOS
{
  p_addresses[p_ip_count] = $1;
  p_ip_count++;
}
;


%%

int yyerror(char *s)
{
  SYSLOG_ERR( s);
}

