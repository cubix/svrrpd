#include "vrrpd.h"

void
advertise_master(vrrp_packet_t * vrrp_pkt, int * sockptr)
{
  int n;
  printf("<<<<Sending Packet>>>>\n");
  db_prt_vrrp_pkt(vrrp_pkt);
  if ((n = send(*sockptr, vrrp_pkt, vrrp_pkt->len, 0)) < 0)
    SYSLOG_ERR("advertise_master: could not send vrrp packet: %m");
}

void
update_arp_tab(vrrp_instance * vrrp_inst)
{
  int i;
  for (i = 0; i < vrrp_inst->pkt->ip_count; i++)
    {
      switch(vrrp_inst->status)
	{ 
	case(MSTR_STAT):
	  arp_op(vrrp_inst->pkt->dyndata[i], vrrp_inst->haddr, SIOCSARP);
	  break;
	case(BKUP_STAT):
	case(SHUTDOWN_STAT):
	  arp_op(vrrp_inst->pkt->dyndata[i], vrrp_inst->haddr, SIOCDARP);
	  break;
	}
    }
}


void
arp_op(uint32_t ip, uchar_t * haddr, int op)
{
  int sockfd, i;
  struct sockaddr_in * sin_paddr;
  struct sockaddr * sin_haddr;
  struct arpreq arp_request;
  unsigned char * uchar_ptr;
  char msg[64], * err;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    SYSLOG_ERR("arp_op: socket creation failed");

  sin_paddr = (struct sockaddr_in *) &arp_request.arp_pa;
  sin_haddr = (struct sockaddr *) &arp_request.arp_ha;
  bzero(sin_paddr, sizeof(struct sockaddr_in));
  bzero(sin_haddr, sizeof(struct sockaddr));
  memcpy(&sin_paddr->sin_addr, &ip, sizeof(unsigned int)); 
  memcpy(&sin_haddr->sa_data, haddr, sizeof(unsigned char) * HADDR_LEN);
  sin_haddr->sa_family = AF_UNSPEC;
  arp_request.arp_flags = ATF_PERM | ATF_PUBL;

  if (ioctl(sockfd, op, &arp_request) < 0)
    {
      switch(op)
	{
	case(SIOCGARP):
	  err = "SIOCGARP";
	  break;
	case(SIOCDARP):
	  err = "SIOCDARP";
	  break;
	case(SIOCSARP):
	  err = "SIOCSARP";
	  break;
	}
      syslog(LOG_ERR, "arp_op: %s operation failed", err);
      exit(1);
    }
  if (op == SIOCGARP)
    memcpy(haddr, &arp_request.arp_ha.sa_data[0], HADDR_LEN);
}

void
grat_arp(vrrp_instance * vrrp_inst)
{
  // Not implemented
}

int *
init_mc_sock(uint32_t  src_addr)
{
  struct ip_mreq mrequest;
  struct in_addr if_addr;
  uchar_t ttl = VRRP_TTL;
  uchar_t loop = FALSE; // if true, multicast data is sent to localhost
  int * sockptr;
  struct sockaddr_in sa;
		
  MALLOC(sockptr, int, sizeof(int), init_mc_sock);

  if ( (*sockptr = socket(AF_INET, SOCK_RAW, VRRP_PROTO)) == -1)
    SYSLOG_ERR("init_mc_sock: socket creation failed: %m");
		
  mrequest.imr_multiaddr.s_addr = inet_addr(VRRP_ADDR_STR);	
  mrequest.imr_interface.s_addr = src_addr;
  if (setsockopt(*sockptr, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mrequest, sizeof(mrequest)) != 0)
    SYSLOG_ERR("init_mc_sock: could not join multicast group: %m");

  if_addr.s_addr = src_addr;
  if (setsockopt(*sockptr, IPPROTO_IP, IP_MULTICAST_IF, &if_addr, sizeof(if_addr)) != 0)
    SYSLOG_ERR("init_mc_sock: could not set default interface: %m");

  if (setsockopt(*sockptr, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0)
    SYSLOG_ERR("init_mc_sock: could not set TTL to 255: %m");

  if (setsockopt(*sockptr, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) != 0)
    SYSLOG_ERR("init_mc_sock: could not disable loopback: %m");

  return sockptr;	
}

void
mc_connect(int * sockptr, uint32_t ip)
{
  struct sockaddr_in sa;
  bzero(&sa, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = ip;

  if (connect(*sockptr, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    SYSLOG_ERR("mc_connect: could not connect socket: %m");
}


vrrp_packet_t *
recv_pkt(int * sockptr)
{
  int n;
  int is_valid = TRUE;
  vrrp_packet_t * vrrp_pkt;
  struct ip_hdr * ip_header;
  vrrp_instance * vrrp_in;
  uchar_t hlen;
  char pktbuf[VRRP_PKTBUF_SIZE];
  if_config_t * ifconf;
  timespec_t adver_int;
  int16_t cs;


  if ((n = recv(*sockptr, pktbuf, sizeof(pktbuf), MSG_WAITALL)) == -1)
    SYSLOG_ERR("recv_pkt: did not recv packet: %m");


  MALLOC(vrrp_pkt, vrrp_packet_t, sizeof(vrrp_packet_t), recv_pkt);

  ip_header = (struct ip_hdr *) pktbuf;
  hlen = ip_header->vers_hlen << 2;
  memcpy(vrrp_pkt,  (vrrp_packet_t *)(pktbuf + hlen), sizeof(vrrp_packet_t));
  vrrp_pkt->src_ip = ip_header->src_ip;
  vrrp_pkt->auth_data_ptr = &vrrp_pkt->dyndata[vrrp_pkt->ip_count];
  vrrp_pkt->len = VRRP_STAT_LEN + (vrrp_pkt->ip_count * sizeof(uint32_t));
  //printf("<<<<Received Packet>>>>\n");
  //db_prt_vrrp_pkt(vrrp_pkt);

  if (ip_header->ttl != VRRP_TTL)
    {
      SYSLOG_WARN("TTL not equal 255");
      is_valid = FALSE;
    }
  else if (vrrp_pkt->vers_type >> 4 != VRRP_VER)
    {
      SYSLOG_WARN("Incorrect VRRP version");
      is_valid = FALSE;
    }
  else if (vrrp_pkt->checksum != vrrp_checksum(vrrp_pkt))
    {
      SYSLOG_WARN("Checksum failed");
      is_valid = FALSE;
    }
  if (is_valid)
    return vrrp_pkt;
  else
    {
      free(vrrp_pkt);
      return NULL;
    }
}
		

void
db_prt_vrrp_pkt(vrrp_packet_t * pkt)
{
  int i;
  struct in_addr addr;
  char auth_data[9];
  auth_data[8] = '\0';
  memcpy(auth_data, pkt->auth_data_ptr, sizeof(uchar_t) * 8);
  printf("Version: %i\tType: %i\n", pkt->vers_type >> 4, pkt->vers_type & 0x0F);
  printf("VRouter ID: %i\tPriority: %i\n", pkt->vrid, pkt->priority);
  printf("IP Count: %i\tAuthentication Type: %i\n", pkt->ip_count, pkt->auth_type);
  printf("Advertisement Interval: %i\tChecksum: %x\n", pkt->adver_int, pkt->checksum);
  printf("IP Addresses:\n");
  for( i = 0; i < pkt->ip_count; i++)
    {
      addr.s_addr = pkt->dyndata[i];
      printf("\t%s\n", inet_ntoa(addr));
    }
  printf("Auth Data: %s\n", pkt->auth_data_ptr);
}

int
vrrp_authenticate(vrrp_packet_t * local, vrrp_packet_t * in)
{
  if (local->auth_type == in->auth_type)
    {
      switch(in->auth_type)
	{
	case AUTH_NONE:
	  return TRUE;

	case AUTH_SIMP:
	  if( memcmp(local->auth_data_ptr,
		     in->auth_data_ptr,
		     sizeof(uint32_t) * AUTH_DATA_SIZE) == 0)
	    return TRUE;
	case AUTH_ENCR:
	  SYSLOG_WARN("authentication type not supported");
	  break;
				
	default:
	  SYSLOG_WARN("unknown authentication type");
						
	}
			
    }
  else
    printf("auth type mismatch");
  printf(": authentication failed\n");
  return FALSE;
}

