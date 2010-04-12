#include "vrrpd.h"

void 
reduce_timespec(timespec_t * time_in) {
  while (time_in->tv_nsec >= 1000)
    {
      time_in->tv_sec++;
      time_in->tv_nsec -= 1000;
    }
}

void
add_timespec(timespec_t * a, timespec_t * b)
{
  a->tv_sec += b->tv_sec;
  a->tv_nsec += b->tv_nsec;
}

void
mult_timespec(timespec_t * time_in, int factor) 
{
  time_in->tv_sec *= factor;
  time_in->tv_nsec *= factor;
}

void
print_timespec(timespec_t * time_in) {
  printf("%is %ims\n", time_in->tv_sec, time_in->tv_nsec);
}


void
freshen_timespec(timespec_t * ts) {
  struct timeval now;
  if (gettimeofday(&now, NULL) < 0) {
    perror("gettimeofday failed!");
    exit(1);
  }
  ts->tv_sec = now.tv_sec;
  ts->tv_nsec = now.tv_usec;
}
