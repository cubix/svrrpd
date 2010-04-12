#include "vrrpd.h"

if_config_t *
create_if_config( unsigned char auth_type, unsigned int * auth_data, uint32_t ip)
{
  if_config_t * new_config;
  MALLOC(new_config, if_config_t, sizeof(if_config_t), create_if_config);

  new_config->auth_type = auth_type;
  memcpy(&new_config->auth_data, auth_data, AUTH_PWD_BUF);
  new_config->src_ip = ip;

  MALLOC(new_config->haddr, uchar_t, sizeof(uchar_t) * HADDR_LEN,
	 create_if_config);

  arp_op(new_config->src_ip, new_config->haddr, SIOCGARP);
		
  return new_config;
}


vrrp_instance *
create_vrrp_instance(	unsigned char vrid, unsigned char priority,
			timespec_t adver_interval, unsigned char preempt_mode,
			ushort_t ip_count, unsigned int * ip_list)
{
  vrrp_instance * new_instance;
  float skew_time; 
  
  MALLOC(new_instance, vrrp_instance, sizeof(vrrp_instance),
	 create_vrrp_instance);	
  new_instance->status = INIT_STAT; 
  new_instance->adver_interval = adver_interval;
  //memcpy(&new_instance->master_down_interval, &adver_interval, sizeof(timespec_t));
  new_instance->master_down_interval = adver_interval;
  mult_timespec(&new_instance->master_down_interval, 3);

  // Calc skew time
  skew_time = (float)(256 - priority) / 256;
  new_instance->skew_time.tv_sec = 0;
  new_instance->skew_time.tv_nsec = skew_time * 1000;
  reduce_timespec(&new_instance->skew_time);
  add_timespec(&new_instance->master_down_interval, &new_instance->skew_time);
  reduce_timespec(&new_instance->master_down_interval);
  new_instance->preempt_mode = preempt_mode;
  MALLOC(new_instance->pkt, vrrp_packet_t, sizeof(vrrp_packet_t),
	 create_vrrp_instance);
  bzero(new_instance->pkt, sizeof(vrrp_packet_t));
  new_instance->pkt->vers_type = 0x21;
  memcpy(&new_instance->pkt->vrid, &vrid, sizeof(uchar_t));
  new_instance->pkt->priority = priority;
  new_instance->pkt->ip_count = ip_count;
  new_instance->pkt->adver_int = adver_interval.tv_sec;
  memcpy(new_instance->pkt->dyndata, ip_list, sizeof(uint32_t) * ip_count);
  new_instance->pkt->auth_data_ptr = &new_instance->pkt->dyndata[ip_count];	
  new_instance->pkt->len = VRRP_STAT_LEN + (ip_count * sizeof(uint32_t));
  new_instance->pkt->checksum = 0;
  return new_instance;
}

uint16_t vrrp_checksum(vrrp_packet_t * pkt)
{
  int nleft = pkt->len;
  uint16_t *w = (uint16_t *) pkt;
  u_short answer;
  int sum = 0;

  /* Make sure checksum field in packet is 0 before doing calculation	  */
  pkt->checksum = 0;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    sum += htons(*(u_char *) w << 8);

  /*
   * add back carry outs from top 16 bits to low 16 bits
   */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */

  return (answer);
}

vrid_node_t *
create_vrid_node( vrrp_instance * instance, vrid_node_t * previous_node)
{
  vrid_node_t * new_node;
  MALLOC(new_node, vrid_node_t, sizeof(vrid_node_t), create_vrid_node);
  new_node->vrrp_inst_ptr = instance;
  new_node->next_node_ptr = NULL;
  if (previous_node != NULL) 
    previous_node->next_node_ptr = new_node;
  return new_node;
}

ifconf_node_t *
create_ifconf_node( if_config_t * ifconf, ifconf_node_t * previous_node)
{
  ifconf_node_t * new_node;
  MALLOC(new_node, ifconf_node_t, sizeof(ifconf_node_t), create_ifconf_node);
  new_node->if_conf_ptr = ifconf;
  new_node->next_node_ptr = NULL;

  if (previous_node != NULL) 
    previous_node->next_node_ptr = new_node;

  return new_node;
}

vrrp_instance **
init_vrrp_table( vrid_node_t * cur_vrid_node )
{
  vrrp_instance **vrrp_tab;
  vrid_t vrid;
  pthread_t * this_tid;
  MALLOC(this_tid, pthread_t, sizeof(pthread_t), init_vrrp_table);
  *this_tid = pthread_self();

  MALLOC(vrrp_tab, vrrp_instance *, sizeof(vrrp_instance *) * MAX_VRID, init_vrrp_table);

  while(cur_vrid_node != NULL)
    {
      vrid = cur_vrid_node->vrrp_inst_ptr->pkt->vrid;
      vrrp_tab[vrid] = cur_vrid_node->vrrp_inst_ptr;
      cur_vrid_node->vrrp_inst_ptr->if_tid = this_tid;
      PT_CREATE(NULL, NULL, adver_thread, cur_vrid_node->vrrp_inst_ptr, init_vrrp_table);
      cur_vrid_node = cur_vrid_node->next_node_ptr;
    }
  return vrrp_tab;
}
