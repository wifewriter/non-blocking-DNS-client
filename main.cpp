//
// Created by yangyang on 2021/5/19.
//
#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include <string>
#include <iostream>

using std::vector;
using std::string;

int n_pending_requests = 0;
struct event_base *base = NULL;

struct user_data {
    char *name;
};

void callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    struct user_data *data = static_cast<user_data *>(ptr);
    const char *name = data->name;
    if (errcode) {
        printf("%d. %s -> %s\n" ,name, evutil_gai_strerror(errcode));
    } else {
        struct evutil_addrinfo *ai;
        printf("%s",name);
        if (addr->ai_canonname)
            printf(" ===>%s", addr->ai_canonname);
        puts("");
        int i =0;
        for (ai = addr; ai; ai = ai->ai_next,i++) {
            char buf[128];
            const char *s = NULL;
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 128);
            }
            if (s)
                printf("resolved_IP_%d:%s\n", i,s);
        }
        evutil_freeaddrinfo(addr);
    }
    free(data->name);
    free(data);
    if (--n_pending_requests == 0)
        event_base_loopexit(base, NULL);
}

vector<string> splitstring(string &str,char *sp){
    vector<string> r;
    while (!str.empty()){
        int index = str.find_first_of(*sp);
        if(index == -1){
            r.push_back(str);
            str.clear();
        } else{
            r.push_back(str.substr(0,index));
            str = str.substr(index+1,str.size()-1);
        }
    }
    return r;
}

int main(int argc, char **argv)
{
    struct evdns_base *dnsbase;

    base = event_base_new();
    if (!base)
        return 1;
    dnsbase = evdns_base_new(base, 1);
    if (!dnsbase)
        return 2;
    string tempstr;
    std::cin>>tempstr;
    vector<string> str_domain;
    str_domain = splitstring(tempstr,",");

    for (auto i = str_domain.begin() ; i !=str_domain.end(); ++i) {
        struct evutil_addrinfo hints;
        struct evdns_getaddrinfo_request *req;
        struct user_data *user_data;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = EVUTIL_AI_CANONNAME;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (!(user_data = static_cast<struct user_data *>(malloc(sizeof(struct user_data))))) {
            perror("malloc");
            exit(1);
        }
        const string str_uname = *i;
        if (!(user_data->name = strdup(str_uname.c_str()))) {
            perror("strdup");
            exit(1);
        }
        ++n_pending_requests;
        req = evdns_getaddrinfo(dnsbase, str_uname.c_str(), NULL,&hints, callback, user_data);
        if (req == NULL) {
            printf("    [request for %s returned immediately]\n", str_uname.c_str());
        }
    }
    if (n_pending_requests)
        event_base_dispatch(base);

    evdns_base_free(dnsbase, 0);
    event_base_free(base);

    return 0;
}
