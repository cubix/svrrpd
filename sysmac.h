#define SYSLOG_NOTICE( loglev, syslog_args) if (loglev <= log_level)	\
    syslog(LOG_NOTICE, syslog_args);

#define SYSLOG_ERR( syslog_args) \
  { syslog(LOG_ERR, syslog_args); exit(1); }

#define SYSLOG_WARN( syslog_args) syslog(LOG_WARNING, syslog_args);

#define MALLOC(ptr, data_type, mem_size, func_name)			\
  if ( (ptr = (data_type*)malloc(mem_size)) == NULL)			\
    {									\
      perror("func_name: malloc failed");				\
      SYSLOG_ERR("func_name: malloc failed: %m");			\
    }

#define PT_MTX_INIT(mutex, func)					\
  if (pthread_mutex_init(&mutex, NULL) != 0)				\
    {									\
      syslog(LOG_ERR, "func: failed to init mutex: %m");		\
      perror("func: failed to init mutex");				\
      exit(1);								\
    }

#define PT_MTX_LOCK(mutex, func)					\
  if (pthread_mutex_lock(&mutex) != 0)					\
    {									\
      syslog(LOG_ERR, "func: failed to lock mutex: %m");		\
      perror("vrrpd: adver_thread: mutex lock failed");			\
      exit(1);								\
    }

#define PT_MTX_UNLOCK(mutex, func)					\
  if (pthread_mutex_unlock(&mutex) != 0)				\
    {									\
      perror("func: mutex unlock failed");				\
      syslog(LOG_ERR, "func: failed to unlock mutex: %m");		\
      exit(1);								\
    }

#define PT_CREATE(tid, attr, thrd_func, arg, func_name)			\
  if (pthread_create(tid, attr, &thrd_func, (void *)arg) != 0)		\
    {									\
      perror("func_name: could not create thread");			\
      SYSLOG_ERR( "func_name: could not create thread: %m");		\
    }
