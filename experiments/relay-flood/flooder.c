// Fast native stranger: T threads, each connects, holds up to H sockets for ms, then RST.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int port, holdms; static double rate_per_thread; static double secs; static volatile long total, errs;
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
typedef struct{int fd;double at;} H;
static void *run(void*a){int cap=holdms?20000:1;H*q=calloc(cap,sizeof(H));int h=0,t=0,n=0;double end=now()+secs;
 struct sockaddr_in s;memset(&s,0,sizeof s);s.sin_family=AF_INET;s.sin_port=htons(port);s.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 struct linger l={1,0};
 while(now()<end){double c=now();
  while(n>0&&(c-q[h].at)*1000>=holdms){close(q[h].fd);h=(h+1)%cap;n--;}
  if(rate_per_thread>0){static __thread double nextat; if(nextat==0)nextat=c; if(c<nextat){usleep((nextat-c)*1e6);} nextat+=1.0/rate_per_thread;}
  int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0){__sync_fetch_and_add(&errs,1);usleep(200);continue;}
  setsockopt(fd,SOL_SOCKET,SO_LINGER,&l,sizeof l);
  if(connect(fd,(void*)&s,sizeof s)!=0){close(fd);__sync_fetch_and_add(&errs,1);continue;}
  __sync_fetch_and_add(&total,1);
  if(holdms==0||n==cap){close(fd);}else{q[t].fd=fd;q[t].at=c;t=(t+1)%cap;n++;}
 }
 while(n>0){close(q[h].fd);h=(h+1)%cap;n--;}return 0;}
int main(int c,char**v){port=atoi(v[1]);secs=atof(v[2]);int T=atoi(v[3]);holdms=atoi(v[4]);
 struct rlimit r;getrlimit(RLIMIT_NOFILE,&r);r.rlim_cur=r.rlim_max>100000?100000:r.rlim_max;setrlimit(RLIMIT_NOFILE,&r);
 if(getenv("RATE"))rate_per_thread=atof(getenv("RATE"))/T;pthread_t p[256];for(int i=0;i<T;i++)pthread_create(&p[i],0,run,0);for(int i=0;i<T;i++)pthread_join(p[i],0);
 printf("{\"connects\":%ld,\"errors\":%ld,\"rate\":%d}\n",total,errs,(int)(total/secs));return 0;}
