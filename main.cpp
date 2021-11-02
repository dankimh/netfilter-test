#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <string>
using namespace std;

struct traffic{
    u_int32_t id;
    bool harm; // 0: harmful, 1: safe
};

string host;
string http_method[9]={"GET","HEAD","POST","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"};

void usage() {
    cout << "syntax: netfilter-test <host>\n";
    cout << "sample: netfilter-test test.gilgil.net\n";
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

string next_line(u_char **payload){
    string ret;
    for(;;){
        if((*payload)[0]=='\n'){
            ret+=(*payload)[0];
            (*payload)++;
            return ret;
        }
        ret+=(*payload)[0];
        (*payload)++;
    }
}

static bool filter_data(u_char *data,size_t size){

    struct libnet_ipv4_hdr *iphdr=(struct libnet_ipv4_hdr*)data;
    if(iphdr->ip_v!=4){
        cerr<<"not an ipv4\n";
        return 1;
    }

    if(iphdr->ip_p!=IPPROTO_TCP){
        cerr<<"not a tcp protocol\n";
        return 1;
    }

    struct libnet_tcp_hdr *tcphdr=(struct libnet_tcp_hdr*)(iphdr+1);
    const u_int8_t tcp_hdr_size=(tcphdr->th_off)*4;

    u_char *payload=(u_char*)(tcphdr)+tcp_hdr_size;

    bool http=false;
    for(int i=0;i<9;i++){
        //cout<<http_method[i]<<"\n";
        //dump(payload,http_method[i].size());
        if(!strncmp((char*)payload,http_method[i].c_str(),http_method[i].size())){
            http=true;
            break;
        }
    }
    if(!http)return 1;

    next_line(&payload);

    string check_host=next_line(&payload);
    //cout<<"check host: "<<check_host<<"\n";
    if(check_host=="Host: "+host+"\r\n")return 0;
    else return 1;
}

/* returns packet id */
static struct traffic print_pkt (struct nfq_data *tb)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
    }

    fputc('\n', stdout);

    //dump(data,ret);

    return {id,filter_data(data,ret)};
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    struct traffic id = print_pkt(nfa);
    cout<<"entering callback "<<id.harm<<"\n";
    return nfq_set_verdict(qh, id.id, id.harm, 0, NULL);
}

void jump_packet(){
    system("sudo iptables -F");
    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
    return;
}

int main(int argc, char **argv)
{

    if(argc!=2){
        usage();
        return -1;
    }

    jump_packet();

    host=argv[1];
    cout<<"host: "<<host<<"\n";

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    cout<<"opening library handle\n";
    h = nfq_open();
    if (!h) {
        cerr<<"error during nfq_open()\n";
        exit(1);
    }

    cout<<"unbinding existing nf_queue handler for AF_INET (if any)\n";
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        cerr<<"error during nfq_unbind_pf()\n";
        exit(1);
    }

    cout<<"binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    if (nfq_bind_pf(h, AF_INET) < 0) {
        cerr<<"error during nfq_bind_pf()\n";
        exit(1);
    }

    cout<<"binding this socket to queue '0'\n";
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        cerr<<"error during nfq_create_queue()\n";
        exit(1);
    }

    cout<<"setting copy_packet mode\n";
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        cerr<<"can't set packet_copy mode\n";
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            cout<<"pkt received\n";
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            cout<<"losing packets!\n";
            continue;
        }
        perror("recv failed");
        break;
    }

    cout<<"unbinding from queue 0\n";
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    cout<<"closing library handle\n";
    nfq_close(h);

    exit(0);
}
