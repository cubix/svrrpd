#include "vrrpd.h"

void sighup_hndlr();
void sigquit_hndlr();
void shutdown_adver();
char ** argv_org;


int main(int argc, char ** argv)
{
  ifconf_node_t * ifnode;
  pthread_t if_tid;
  char * cfile = CONF;
  int sig, c, i, arglen, errflag = 0, thrd_count = 0, fd, conf_stdin_flag = FALSE, foreground_flag = FALSE;
  extern int optind, opterr;
  extern char * optarg;
  pid_t pid;
  sigset_t sig_set;
	  
  openlog("vrrpd", LOG_PID | LOG_CONS, LOG_DAEMON);
  SYSLOG_NOTICE(LOG_LEV1, "VRRP daemon started");
	  
  MALLOC(argv_org, char *, sizeof(char *) * (argc+1), main);
		
		
  for (i = 0; i < argc; i++)
    {
      arglen = sizeof(char) * (strlen(argv[i]) + 1);
      MALLOC(argv_org[i], char, arglen, main);
      memcpy(argv_org[i], argv[i], arglen);
    }
  argv_org[++i] = NULL;
  opterr = FALSE;
  while ( (c = getopt(argc, argv, "f:idD")) != EOF)
    {
      switch(c)
	{
	case 'f':
	  cfile = optarg;	
	  break;
	case 'i':
	  conf_stdin_flag = TRUE;
	  break;
	case 'd':
	  foreground_flag = FALSE;
	  break;
	case 'D':
	  foreground_flag = TRUE;
	  break;
	case '?':
	  errflag = TRUE;
	}
    }
	  
  if (errflag == TRUE)
    {
      fprintf(stderr, "usage: %s [-f <conf>] [-idD]\n", argv[0]);
      fprintf(stderr, "\t\t-f <conf>\t\tPath to config file\n");
      fprintf(stderr, "\t\t-i\t\t\tUse stdin\n");
      fprintf(stderr, "\t\t-D\t\t\tDo not detach form term\n");
      fprintf(stderr, "\t\t-d\t\t\tDetach from term (default)\n\n");
      SYSLOG_ERR("main: invalid command arguments");
    }
	  
  if (foreground_flag == FALSE)
    {
      switch(pid = fork ())
	{
	case(-1): 
	  syslog(LOG_ERR, "main: cannot fork: %m");
	  fprintf(stderr, "vrrpd: main: cannot fork\n");
	  exit(1);
		  
	case(0):
	  fd = open ("/dev/null", O_RDWR);
	  if (fd > 0)
	    {
	      dup2(fd, 0);
	      dup2(fd, 1);
	      dup2(fd, 2);
	    }
		  
	  setsid();
	  break;

	default:
	  exit(0);
	}
	      
    }
	  
  if (conf_stdin_flag == FALSE)
    {
      if ((yyin = fopen(cfile, "r")) == NULL)
	{
	  syslog(LOG_ERR, "main: could not open \"%s\": %m", cfile);
	  fprintf(stderr, "vrrpd: could not open \"%s\": %s\n", cfile, strerror(errno));
	  exit(1);
	}
    }
  ifcount = 0;
	  
  yyparse();
  ifnode = p_head_ifconf_node;
  while (ifnode != NULL)
    {
      PT_CREATE(NULL, NULL, if_thread, ifnode->if_conf_ptr, main);
      ifnode = ifnode->next_node_ptr;
    }
	  
  signal(SIGHUP, (void *)&sighup_hndlr);
  signal(SIGQUIT, (void *)&sigquit_hndlr);
  signal(SIGTERM, (void *)&sigquit_hndlr);
  signal(SIGINT, (void *)&sigquit_hndlr);
  sigemptyset(&sig_set);
  sigwait(&sig_set, &sig);
  return 0;
}

void sighup_hndlr(void)
{
  signal(SIGHUP, (void *)&sighup_hndlr);
  SYSLOG_NOTICE(LOG_LEV1, "VRRP daemon is being restarted");
  shutdown_adver();
  execv(argv_org[0], argv_org);
  SYSLOG_ERR( "sighup_hndlr: failed restarting VRRP daemon with execv: %m");
  return;
}

void sigquit_hndlr(void)
{
  signal(SIGQUIT, (void *)&sigquit_hndlr);
  SYSLOG_NOTICE(LOG_LEV1, "VRRP daemon is shutting down");
  shutdown_adver();
  exit(0);
}


void shutdown_adver(void)
{
  ifconf_node_t * ifnode;
  vrid_node_t * vnode;
  vrrp_instance * vrrp_inst;

  ifnode = p_head_ifconf_node;
  while(ifnode != NULL)
    {
      vnode = ifnode->if_conf_ptr->head_node;
      while (vnode != NULL)
	{
	  vrrp_inst = vnode->vrrp_inst_ptr;
	  PT_MTX_LOCK(vrrp_inst->vrrp_mutex, shutdown_adver);
	  if (vrrp_inst->status == MSTR_STAT)
	    {
	      vrrp_inst->status = SHUTDOWN_STAT;
	      pthread_cond_signal(&vrrp_inst->vrrp_cond);
	    }
	  PT_MTX_UNLOCK(vrrp_inst->vrrp_mutex, shutdown_adver);
	  vnode = vnode->next_node_ptr;
	}	
      ifnode = ifnode->next_node_ptr;
    }
}


void * adver_thread(void *arg)
{
  vrrp_instance * vrrp_inst = (vrrp_instance *)arg;
  int err_status;
  int locked = 0;
  timespec_t * timeout;
  int * sendsock;
  
  if (log_level >= LOG_LEV2)
    syslog(LOG_NOTICE, "advertisement thread created");
  PT_MTX_INIT(vrrp_inst->vrrp_mutex, adver_thread);
  PT_MTX_LOCK(vrrp_inst->vrrp_mutex, adver_thread);

  if (vrrp_inst->pkt->priority < MAX_VRID)
    vrrp_inst->status = BKUP_STAT;

  freshen_timespec(&vrrp_inst->abs_timer);

  if (vrrp_inst->pkt->priority < MAX_VRID)
    add_timespec(&vrrp_inst->abs_timer, &vrrp_inst->master_down_interval);
  
  PT_MTX_UNLOCK(vrrp_inst->vrrp_mutex, adver_thread);
  
  sendsock = init_mc_sock(vrrp_inst->pkt->src_ip);
  mc_connect(sendsock, inet_addr(VRRP_ADDR_STR));
  
  while(1)
    {
      
      err_status = pthread_cond_timedwait(&vrrp_inst->vrrp_cond,
					  &vrrp_inst->vrrp_mutex,
					  &vrrp_inst->abs_timer);
      if (err_status && err_status != ETIMEDOUT)
	{
	  printf("pthread_cond_timedwait failed! %i", err_status);
	  exit(1);
	}
      if (vrrp_inst->status == SHUTDOWN_STAT)
	{
	  vrrp_inst->pkt->priority = 0;
	  vrrp_inst->pkt->checksum = 0;
	  vrrp_inst->pkt->checksum = vrrp_checksum(vrrp_inst->pkt);
	  update_arp_tab(vrrp_inst);
	  advertise_master(vrrp_inst->pkt, sendsock);
	  PT_MTX_UNLOCK(vrrp_inst->vrrp_mutex, adver_thread)
	    if (log_level >= LOG_LEV2)
	      syslog(LOG_NOTICE, "shutting down VRID %i", vrrp_inst->pkt->vrid);
	  pthread_exit(NULL);
	}
      // Timed out, so advertise
      else if (err_status)
	{
	  freshen_timespec(&vrrp_inst->abs_timer);
	  add_timespec(&vrrp_inst->abs_timer, &vrrp_inst->adver_interval);
	  advertise_master(vrrp_inst->pkt, sendsock);
	  if (vrrp_inst->status != MSTR_STAT)
	    {
	      if (log_level >= LOG_LEV1)
		syslog(LOG_NOTICE, "changing state of VRID %i to MASTER",
		       vrrp_inst->pkt->vrid);
	      vrrp_inst->status = MSTR_STAT;
	      update_arp_tab(vrrp_inst);
	      grat_arp(vrrp_inst);
	    }
	}
      else
	{
	  if (vrrp_inst->status != BKUP_STAT)
	    {
	      vrrp_inst->status = BKUP_STAT;
	      if (log_level >= LOG_LEV1)
		syslog(LOG_NOTICE, "changing state of VRID %i to BACKUP",
		       vrrp_inst->pkt->vrid);
	    }
	}
      
      PT_MTX_UNLOCK(vrrp_inst->vrrp_mutex, adver_thread);
    }
}

void *
if_thread(void *arg)
{
  if_config_t * conf = (if_config_t *)arg;
  vrrp_instance ** vrrp_tab;
  vrrp_packet_t * recvd_vrrp;
  int * sockptr;

  if (log_level >= LOG_LEV2)
    syslog(LOG_NOTICE, "if_thread created");
  
  if (pthread_detach(pthread_self()) != 0)
    {
      syslog(LOG_ERR, "failed to detach interface thread: %m");
      perror("vrrpd: adver_thread: could not detach thread");
      exit(1);
    }

  vrrp_tab = init_vrrp_table(conf->head_node);
  sockptr = init_mc_sock(conf->src_ip);
		
  while(1) {
    recvd_vrrp = recv_pkt(sockptr);
    if (recvd_vrrp != NULL && vrrp_authenticate(vrrp_tab[recvd_vrrp->vrid]->pkt, recvd_vrrp))
      {
	pthread_mutex_lock(&vrrp_tab[recvd_vrrp->vrid]->vrrp_mutex);
	freshen_timespec(&vrrp_tab[recvd_vrrp->vrid]->abs_timer);
	if (vrrp_tab[recvd_vrrp->vrid]->status == BKUP_STAT)
	  {
	    if (recvd_vrrp->priority == 0)
	      {
		add_timespec(&vrrp_tab[recvd_vrrp->vrid]->abs_timer,
			     &vrrp_tab[recvd_vrrp->vrid]->skew_time);
		pthread_cond_signal(&vrrp_tab[recvd_vrrp->vrid]->vrrp_cond);
	      }
	    else if (vrrp_tab[recvd_vrrp->vrid]->preempt_mode == 0
		     || recvd_vrrp->priority >= vrrp_tab[recvd_vrrp->vrid]->pkt->priority)
	      {
		
		add_timespec(&vrrp_tab[recvd_vrrp->vrid]->abs_timer,
			     &vrrp_tab[recvd_vrrp->vrid]->master_down_interval);
		pthread_cond_signal(&vrrp_tab[recvd_vrrp->vrid]->vrrp_cond);
	      }
	  }
	else if (vrrp_tab[recvd_vrrp->vrid]->status == MSTR_STAT)
	  {
	    if (recvd_vrrp->priority == 0)
	      {
		// send adver now
		pthread_cond_signal(&vrrp_tab[recvd_vrrp->vrid]->vrrp_cond);
	      }
	    else if (recvd_vrrp->priority > vrrp_tab[recvd_vrrp->vrid]->pkt->priority
		     || recvd_vrrp->priority == vrrp_tab[recvd_vrrp->vrid]->pkt->priority
		     && recvd_vrrp->src_ip > vrrp_tab[recvd_vrrp->vrid]->pkt->src_ip)
	      {
		
		add_timespec(&vrrp_tab[recvd_vrrp->vrid]->abs_timer,
			     &vrrp_tab[recvd_vrrp->vrid]->master_down_interval);
		pthread_cond_signal(&vrrp_tab[recvd_vrrp->vrid]->vrrp_cond);
	      }
	  }
	PT_MTX_UNLOCK(vrrp_tab[recvd_vrrp->vrid]->vrrp_mutex, if_thread);
	free(recvd_vrrp);
      }
    else if (recvd_vrrp == NULL)
      break;	
  }
}

