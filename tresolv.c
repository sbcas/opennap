#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include "tresolv.h"

struct lookup {
    unsigned int ip;
    char **out;
};

static void *
query_thread(void *arg)
{
    struct in_addr in;
    struct lookup *l = arg;
    char *host;
    struct hostent *he;

    pthread_detach(pthread_self());
    in.s_addr=l->ip;
    //printf("looking up %s\n",inet_ntoa(in));
    he=gethostbyaddr((char*)&in,sizeof(in),AF_INET);
    if(he)
	host=strdup(he->h_name);
    else
	host=strdup(inet_ntoa(in));
    //printf("%s is %s\n",inet_ntoa(in), host);
    *l->out=host;
    free(l);
    return NULL;
}

void
query_ip(unsigned int ip, char **arg)
{
    struct lookup *l;
    pthread_t tid;

    l=malloc(sizeof(struct lookup));
    l->ip=ip;
    l->out=arg;
    *arg=QUERY_PENDING;
    pthread_create(&tid,NULL,query_thread,l);
}
