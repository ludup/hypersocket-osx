//
//  RedirectNKE.c
//  RedirectNKE
//
//  Created by Lee Painter on 26/11/2013.
//  Copyright (c) 2013 Hypersocket Limited. All rights reserved.
//

#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kpi_mbuf.h>
#include <sys/kern_control.h>
#include <i386/endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/kpi_ipfilter.h>

#include <libkern/OSMalloc.h>

#include "RedirectNKE.h"

kern_return_t RedirectNKE_start (kmod_info_t * ki, void * d);
kern_return_t RedirectNKE_stop (kmod_info_t * ki, void * d);

enum {
    kMyFiltDirIn,
    kMyFiltDirOut,
    kMyFiltRedirIn,
    kMyFiltRedirOut
};


static ipfilter_t g_filter_ref;
static boolean_t g_filter_registered = FALSE;
static boolean_t g_filter_detached = FALSE;
static kern_ctl_ref g_ctl_ref;
static struct timeval g_last_clean_and_stats;
static int g_connected_clients;

static OSMallocTag		g_osm_tag;

static lck_mtx_t        *g_mutex = NULL;
static lck_grp_t        *g_mutex_group = NULL;

static boolean_t log_redirected_packets = FALSE;
static boolean_t log_other_packets = FALSE;

TAILQ_HEAD(redirection_list, redirection);
static struct redirection_list g_redirection_list;

TAILQ_HEAD(redirect_rules, redirect_rule);
static struct redirect_rules g_rule_list;

struct redirect_rule {
    TAILQ_ENTRY(redirect_rule)   link; 
    in_addr_t network_addr;
    in_addr_t subnet_mask;
    in_addr_t forward_to_ip;
    unsigned short forward_to_port;
};

struct redirection {
    TAILQ_ENTRY(redirection)   link; 
    in_addr_t source_ip;
    unsigned short source_port;
    in_addr_t dest_ip;
    unsigned short dest_port;
    in_addr_t forward_to_ip;
    unsigned short forward_to_port;
    boolean_t source_fin;
    int source_fin_ack_seq;
    boolean_t source_ack;
    boolean_t dest_fin;
    int dest_fin_ack_seq;
    boolean_t dest_ack;
    boolean_t rst;
    struct timeval last_packet;
};

/*
 * Messages to the system log
 */

static void
log(const char *fmt, ...)
{
	va_list listp;
	char log_buffer[512];
    
	va_start(listp, fmt);
    
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("RedirectNKE: %s\n", log_buffer);
    
	va_end(listp);
}

static void log_redirection(struct redirection* redirect, const char* info)
{
    
    char src[32], dst[32];
    bzero(src, sizeof(src));
    bzero(dst, sizeof(dst));
    inet_ntop(AF_INET, &redirect->source_ip, src, sizeof(src));
    inet_ntop(AF_INET, &redirect->dest_ip, dst, sizeof(dst));
    
    log("%s %s:%d > %s:%d source fin=%d ack=%d dest fin=%d ack=%d", 
        info,
        src, 
        ntohs(redirect->source_port), 
        dst, 
        ntohs(redirect->dest_port),
        redirect->source_fin, 
        redirect->source_ack, 
        redirect->dest_fin, 
        redirect->dest_ack);
    
}

static void log_ip_packet(mbuf_t *data, int dir, const char* info)
{
    lck_mtx_lock(g_mutex);
    
    char src[32], dst[32];
    unsigned char *ptr = (unsigned char*)mbuf_data(*data);
    struct ip *ip = (struct ip*) (struct ip*)ptr;
    
    if (ip->ip_v != 4)
        return;
    
    bzero(src, sizeof(src));
    bzero(dst, sizeof(dst));
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("RedirectNKE: TCP ");
            switch(dir) {
                case kMyFiltDirIn:
                    printf("[IN]  ");
                    break;
                case kMyFiltDirOut:
                    printf("[OUT] ");
                    break;
                case kMyFiltRedirIn:
                    printf("[RIN] ");
                    break;
                case kMyFiltRedirOut:
                    printf("[ROU] ");
                    break;
                default:
                    break;
            }
            struct tcphdr *tcp = (struct tcphdr*) (ptr + (ip->ip_hl << 2));
            printf("%s:%d > %s:%d %s\n", src, ntohs(tcp->th_sport), dst, ntohs(tcp->th_dport), info);
            break;
        default:
            break;
    }
    
    lck_mtx_unlock(g_mutex);
    
}

static void log_rule(const char* info, in_addr_t network_addr, in_addr_t subnet_mask, in_addr_t forward_to_ip, unsigned short forward_port)
{
    
    char net[32];
    bzero(net, sizeof(net));
    inet_ntop(AF_INET, &network_addr, net, sizeof(net));
    
    char sub[32];
    bzero(sub, sizeof(sub));
    inet_ntop(AF_INET, &subnet_mask, sub, sizeof(sub));
    
    char fwd[32];
    bzero(fwd, sizeof(fwd));
    inet_ntop(AF_INET, &forward_to_ip, fwd, sizeof(fwd));
    
    log("%s network %s subnet mask %s forwarding to %s:%d", info, net, sub, fwd, forward_port);
    
}

static struct redirect_rule *
find_rule_by_network(in_addr_t network_addr, in_addr_t subnet_mask)
{
	struct redirect_rule *entry, *next_entry;
    struct redirect_rule *result = NULL;
    lck_mtx_lock(g_mutex);
    
    
    for (entry = TAILQ_FIRST(&g_rule_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        if (entry->network_addr == network_addr && 
            entry->subnet_mask == subnet_mask) {
            result = entry;
            break;
        }
    }
    
    lck_mtx_unlock(g_mutex);
    return result;
}

static struct redirect_rule *
find_rule_by_destination_ip(in_addr_t ip)
{
	struct redirect_rule *entry, *next_entry;
    struct redirect_rule *result = NULL;
    
    lck_mtx_lock(g_mutex);
    
    for (entry = TAILQ_FIRST(&g_rule_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        if ((ip & entry->subnet_mask) == (entry->network_addr & entry->subnet_mask)) {
            result = entry;
            break;
        }
    }
    
    lck_mtx_unlock(g_mutex);
    
    return result;
}

static struct redirection* add_redirection(in_addr_t source_ip, unsigned short source_port, in_addr_t dest_ip, unsigned short  dest_port, in_addr_t forward_to_ip, unsigned short forward_port)
{
    struct redirection* entry = NULL;
    struct redirection* result = NULL;
    
    lck_mtx_lock(g_mutex);
    
    entry = OSMalloc(sizeof(struct redirection), g_osm_tag);
    bzero(entry, sizeof(struct redirection));
    
    if (entry)
    {
        entry->source_ip = source_ip;
        entry->source_port = source_port;
        entry->dest_ip = dest_ip;
        entry->dest_port = dest_port;
        entry->forward_to_ip = forward_to_ip;
        entry->forward_to_port = forward_port;
        
        getmicrotime(&entry->last_packet);
        
        TAILQ_INSERT_TAIL(&g_redirection_list, entry, link);
        
        result = entry;
    }
    
    lck_mtx_unlock(g_mutex);
	
	return result;
    
}


static struct redirection *
find_input_redirection(in_addr_t dest_ip, unsigned short dest_port)
{
	struct redirection *entry, *next_entry;
    struct redirection* result = NULL;
    
    lck_mtx_lock(g_mutex);
    
    for (entry = TAILQ_FIRST(&g_redirection_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        if (entry->source_ip == dest_ip && entry->source_port == dest_port) {
            result = entry;
            break;
        }
    }
    
    lck_mtx_unlock(g_mutex);
    
    return result;
}

static struct redirection *
find_output_redirection(in_addr_t source_ip, unsigned short source_port)
{
    
    struct redirection *entry, *next_entry;
    struct redirection* result = NULL;
    
    lck_mtx_lock(g_mutex);
    
    for (entry = TAILQ_FIRST(&g_redirection_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        if (entry->source_ip == source_ip && entry->source_port == source_port) {
            result = entry;
            break;
        }
    }
    
    lck_mtx_unlock(g_mutex);
    
    return result;
    
}

static struct redirection *
find_or_create_output_redirection(in_addr_t source_ip, unsigned short source_port,
                                  in_addr_t dest_ip, unsigned short dest_port)
{
    
    struct redirection* entry = find_output_redirection(source_ip, source_port);
    
    if(entry)
        return entry;
    
    struct redirect_rule* rule = find_rule_by_destination_ip(dest_ip);
    if(rule) 
    {
        return add_redirection(source_ip, source_port, dest_ip, dest_port, rule->forward_to_ip, rule->forward_to_port);
    }
    else {
        return NULL;
    }
}

static int remove_rule(in_addr_t network_addr, in_addr_t subnet_mask, in_addr_t forward_to_ip, unsigned short forward_port)
{
    struct redirect_rule *entry, *next_entry;
    int result = KERN_FAILURE;
    lck_mtx_lock(g_mutex);
    
    log_rule("Removing rule for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
    
    for (entry = TAILQ_FIRST(&g_rule_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        if (entry->network_addr == network_addr 
            && entry->subnet_mask == subnet_mask
            && entry->forward_to_ip == forward_to_ip
            && entry->forward_to_port == forward_port) {
            
            
            TAILQ_REMOVE(&g_rule_list, entry, link);
            
            log_rule("Found and removed rule for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
            
            result = KERN_SUCCESS;
            break;
        }
    }
    
    lck_mtx_unlock(g_mutex);
    
    if(result==KERN_FAILURE) {
        log_rule("Rule not found for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
    }
    
    return result;
}

static int add_rule(in_addr_t network_addr, in_addr_t subnet_mask, in_addr_t forward_to_ip, unsigned short forward_port)
{
    int ret = 0;
    struct redirect_rule* entry = NULL;
    
    log_rule("Adding rule for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
    
    entry = find_rule_by_network(network_addr, subnet_mask);
    if (entry)
    {
        entry->forward_to_ip = forward_to_ip;
        entry->forward_to_port = forward_port;
        
        log_rule("Found and updated rule for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
    }
    else
    {
        
        entry = OSMalloc(sizeof(struct redirect_rule), g_osm_tag);
        if (!entry)
        {
            log("Not enough memory to allocate redirection rule");
            ret = ENOMEM;
            lck_mtx_unlock(g_mutex);
            return ret;
        }
        
        
        
        entry->network_addr = network_addr;
        entry->subnet_mask = subnet_mask;
        entry->forward_to_ip = forward_to_ip;
        entry->forward_to_port = forward_port;
        
        lck_mtx_lock(g_mutex);
        
        TAILQ_INSERT_TAIL(&g_rule_list, entry, link);
        
        log_rule("Added rule for", network_addr, subnet_mask, forward_to_ip, ntohs(forward_port));  
        
        lck_mtx_unlock(g_mutex);
        
    }
    
	return ret;
    
}


static void cleanRules(void) {
    
    log("Cleaning rule data");
    
    struct redirect_rule *entry, *next_entry;
    
    for (entry = TAILQ_FIRST(&g_rule_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        TAILQ_REMOVE(&g_rule_list, entry, link);
        OSFree(entry, sizeof(struct redirect_rule), g_osm_tag);
    }
}

static void cleanRedirection(void) {
    
    log("Cleaning redirection data");
    
    struct redirection *entry, *next_entry;
    for (entry = TAILQ_FIRST(&g_redirection_list); entry; entry = next_entry) 
    {
        next_entry = TAILQ_NEXT(entry, link);
        TAILQ_REMOVE(&g_redirection_list, entry, link);
        OSFree(entry, sizeof(struct redirection), g_osm_tag);
    }
    
}

static void filter_update_cksum(mbuf_t data)
{
    u_int16_t ip_sum;
    u_int16_t tsum;
    struct tcphdr* tcp;
    struct udphdr* udp;
    
    unsigned char *ptr = (unsigned char*)mbuf_data(data);
    
    struct ip *ip = (struct ip*)ptr;
    if (ip->ip_v != 4)
        return;
    
    ip->ip_sum = 0;
    mbuf_inet_cksum(data, 0, 0, ip->ip_hl << 2, &ip_sum); // ip sum
    
    ip->ip_sum = ip_sum;
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct tcphdr*)(ptr + (ip->ip_hl << 2));
            tcp->th_sum = 0;
            mbuf_inet_cksum(data, IPPROTO_TCP, ip->ip_hl << 2, ntohs(ip->ip_len) - (ip->ip_hl << 2), &tsum);
            tcp->th_sum = tsum;
            break;
        case IPPROTO_UDP:
            udp = (struct udphdr*)(ptr + (ip->ip_hl << 2));
            udp->uh_sum = 0;
            mbuf_inet_cksum(data, IPPROTO_UDP, ip->ip_hl << 2, ntohs(ip->ip_len) - (ip->ip_hl << 2), &tsum);
            udp->uh_sum = tsum;
            break;
        default:
            break;
    }
    
    mbuf_clear_csum_performed(data); // Needed?
}

static boolean_t is_redirection_closed(struct redirection* redirect)
{
    return (redirect->source_fin && 
            redirect->source_ack && 
            redirect->dest_fin && 
            redirect->dest_ack);
    
}

static boolean_t is_redirection_closing(struct redirection* redirect) 
{
    return (redirect->source_fin ||
            redirect->dest_fin);   
}

static void check_close_state(struct redirection* redirect, mbuf_t *data, int dir) 
{
    if(is_redirection_closed(redirect) 
       || redirect->rst) {
        
        // Put redirect into close wait
        
        if(log_redirected_packets)
            log_ip_packet(data, dir, "*** Closed ***");
        
        lck_mtx_lock(g_mutex);
        
        TAILQ_REMOVE(&g_redirection_list, redirect, link);
        
        lck_mtx_unlock(g_mutex);
    }
    
}

static void check_clean_and_stats()
{
    // Check clean state every minute and output stats
    struct timeval t;
    getmicrotime(&t);
    
    if(t.tv_sec - g_last_clean_and_stats.tv_sec > 60) {
        
        lck_mtx_lock(g_mutex);
        
        int total_redirects = 0;
        int in_closing_state = 0;
        int forced_closed = 0;
        
        log("Current Stats");
        
        struct redirection *entry, *next_entry;
        for (entry = TAILQ_FIRST(&g_redirection_list); entry; entry = next_entry) 
        {
            next_entry = TAILQ_NEXT(entry, link);
            total_redirects++;
            if(is_redirection_closing(entry)) {
                in_closing_state++;
                if(t.tv_sec - entry->last_packet.tv_sec > 240) {
                    
                    log_redirection(entry, "CLOSED ");
                    
                    TAILQ_REMOVE(&g_redirection_list, entry, link);
                    OSFree(entry, sizeof(struct redirection), g_osm_tag);
                    forced_closed++;
                } else {
                    log_redirection(entry, "CLOSING");
                }
            } else {
                log_redirection(entry, "OPEN   ");
            }
        }
        
        lck_mtx_unlock(g_mutex);
        
        log("Total Active Redirects:     %d", total_redirects - forced_closed);
        log("Redirects in Closing State: %d", in_closing_state);
        log("Forced Close:               %d", forced_closed);
        
        getmicrotime(&g_last_clean_and_stats);
        
    }
    
    
}

static errno_t filter_output_redirect(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    // Find an existing redirection rule based on source ip:port and change destination, if
    // a current redirection does not exist create one to record the original destination for
    // future look ups
    
    unsigned char *ptr = (unsigned char*)mbuf_data(*data);
    struct ip *ip = (struct ip*) (struct ip*)ptr;
    
    int ret;
    
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return 0;
    
    struct tcphdr *tcp = (struct tcphdr*) (ptr + (ip->ip_hl << 2));
    
    struct redirection* redirect = find_or_create_output_redirection(ip->ip_src.s_addr, 
                                                                     tcp->th_sport,
                                                                     ip->ip_dst.s_addr, 
                                                                     tcp->th_dport);
    if(redirect)
    {
        
        ip->ip_dst.s_addr = redirect->forward_to_ip;
        tcp->th_dport = redirect->forward_to_port;    
        
        filter_update_cksum(*data);
        
        ret = ipf_inject_output(*data, g_filter_ref, options);
        
        if(log_redirected_packets)
            log_ip_packet(data, kMyFiltRedirOut, "");
        
        
        if(tcp->th_flags & TH_FIN) {
            redirect->source_fin = TRUE;
            redirect->source_fin_ack_seq = tcp->th_ack;
            
            if(log_redirected_packets)
                log_redirection(redirect, "SRC FIN");
            
        } else if(redirect->dest_fin && tcp->th_flags & TH_ACK && redirect->dest_fin_ack_seq == tcp->th_seq) {
            redirect->dest_ack = TRUE;
            
            if(log_redirected_packets)
                log_redirection(redirect, "DST FINACK");
            
            check_close_state(redirect, data, kMyFiltRedirOut);
        } else if(tcp->th_flags & TH_RST) {
            redirect->rst = TRUE;
            
            if(log_redirected_packets)
                log_redirection(redirect, "SRC RST");
            
            
            check_close_state(redirect, data, kMyFiltRedirOut);
        }
        
        
        return ret == 0 ? EJUSTRETURN : ret;
    }
    
    check_clean_and_stats();
    
    return 0;
}

static errno_t filter_input_redirect(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
    
    // Find the original source ip:port from the destination in ip header
    // and update ip header source ip:port to reflect
    
    unsigned char *ptr = (unsigned char*)mbuf_data(*data);
    struct ip *ip = (struct ip*) (struct ip*)ptr;
    
    int ret;
    
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return 0;
    
    struct tcphdr *tcp = (struct tcphdr*) (ptr + (ip->ip_hl << 2));
    
    struct redirection* redirect = find_input_redirection(ip->ip_dst.s_addr, 
                                                          tcp->th_dport);
    if(redirect)
    {
        
        ip->ip_src.s_addr = redirect->dest_ip;
        tcp->th_sport = redirect->dest_port;    
        
        filter_update_cksum(*data);
        
        if(log_redirected_packets)
            log_ip_packet(data, kMyFiltRedirIn, "");
        
        ret = ipf_inject_input(*data, g_filter_ref);
        
        if(tcp->th_flags & TH_FIN) {
            redirect->dest_fin = TRUE;
            redirect->dest_fin_ack_seq = tcp->th_ack;
            
            if(log_redirected_packets)
                log_redirection(redirect, "DST FIN");
            
            
        } else if(redirect->source_fin && tcp->th_flags & TH_ACK && tcp->th_seq == redirect->source_fin_ack_seq) {
            redirect->source_ack = TRUE;
            
            if(log_redirected_packets)
                log_redirection(redirect, "SRC FINACK");
            
            
            check_close_state(redirect, data, kMyFiltRedirIn);
        } else if(tcp->th_flags & TH_RST) {
            redirect->rst = TRUE;
            
            if(log_redirected_packets)
                log_redirection(redirect, "DST RST");
            
            
            check_close_state(redirect, data, kMyFiltRedirIn);
        }
        
        
        return ret == 0 ? EJUSTRETURN : ret;
    }
    
    check_clean_and_stats();
    
    return 0;
}



static errno_t filter_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    if (data && log_other_packets)
        log_ip_packet(data, kMyFiltDirOut, "");
    
    return filter_output_redirect(cookie, data, options);
    
}

static errno_t filter_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
    if (data && log_other_packets)
        log_ip_packet(data, kMyFiltDirIn, "");
    
    return filter_input_redirect(cookie, data, offset, protocol);
}

static void filter_detach(void *cookie)
{
    log("Filter detached");
    
    g_filter_detached = TRUE;
}

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void** unit_info)
{
    
    g_connected_clients++;
    
    log("Process with pid=%d connected", proc_selfpid());
    
    return 0;
}

static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void* unit_info)
{
    
    g_connected_clients--;
    
    log("Process with pid=%d disconnected", proc_selfpid());
    
    return 0;
}

static errno_t ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void* unit_info, int opt, void *data, size_t* len)
{
    
    switch(opt) {
        case REDIRECTNKE_GET_ORIGINAL_DESTINATION:
        {
            
            if(*len < ((sizeof(unsigned short) * 2) + (sizeof(in_addr_t) * 2))) {
                log("HERMIT_GET_ORIGINAL_DESTINATION Failure: %d bytes is not enough data to hold in_addr_t and ushort", *len);
                return KERN_FAILURE;
            }
            
            void* tmp = data;
            
            in_addr_t source_ip = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            unsigned short source_port = *(unsigned short*)tmp;
            tmp += sizeof(unsigned short);
            in_addr_t forward_ip = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            unsigned short forward_port = *(unsigned short*)tmp;
            
            char src[32];
            bzero(src, sizeof(src));
            inet_ntop(AF_INET, &source_ip, src, sizeof(src));
            
            char fwd[32];
            bzero(fwd, sizeof(fwd));
            inet_ntop(AF_INET, &forward_ip, fwd, sizeof(fwd));
            
            log("Client is requesting original destination for source %s:%d forwarding to %s:%d", src, source_port, fwd, forward_port);
            
            struct redirection* redirect = find_output_redirection(source_ip, htons(source_port));
            
            if(!redirect) {
                
                log("No active redirection for source %s:%d", src, source_port);
                
                return EADDRNOTAVAIL;
            } else if(redirect->forward_to_ip != forward_ip 
                      || redirect->forward_to_port != htons(forward_port)) {
                
                bzero(fwd, sizeof(fwd));
                inet_ntop(AF_INET, &redirect->forward_to_ip, fwd, sizeof(fwd));
                log("Forwarding socket does not match redirect entry forward of %s:%d", fwd, ntohs(redirect->forward_to_port));
                
                return EAFNOSUPPORT;
            }
            
            
            char dst[32];
            bzero(dst, sizeof(dst));
            inet_ntop(AF_INET, &redirect->dest_ip, dst, sizeof(dst));
            
            log("Found redirection from source %s:%d to %s:%d", src, source_port, dst, ntohs(redirect->dest_port));
            
            memcpy(data, &redirect->dest_ip, sizeof(in_addr_t));
            
            memcpy(data+sizeof(in_addr_t), &redirect->dest_port, sizeof(unsigned short));
            
            return KERN_SUCCESS;
        }
        default:
        {
            log("Operation not supported");
            return ENOTSUP;
        }
    }
}

static errno_t ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void* unit_info, int opt, void *data, size_t len)
{
#ifdef DEBUG
    log("Entered ctl_set");
#endif
    switch(opt) {
        case REDIRECTNKE_ADD_REDIRECTION:
        {
#ifdef DEBUG
            log("ctl_set Add Rule");
#endif
            void* tmp = data;
            
            in_addr_t network_addr = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            in_addr_t subnet_mask = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            in_addr_t forward_ip = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            unsigned short forward_port = *(unsigned short*)tmp;
            
            int ret = add_rule(network_addr, subnet_mask, forward_ip, htons(forward_port));
            
            if(ret != 0)
                return KERN_FAILURE;
            else 
                return KERN_SUCCESS;
        }
        case REDIRECTNKE_REMOVE_REDIRECTION:
        {
#ifdef DEBUG
            log("ctl_set Remove Rule");
#endif
            void* tmp = data;
            
            in_addr_t network_addr = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            in_addr_t subnet_mask = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            in_addr_t forward_ip = *(in_addr_t*)tmp;
            tmp += sizeof(in_addr_t);
            unsigned short forward_port = *(unsigned short*)tmp;
            
            int ret = remove_rule(network_addr, subnet_mask, forward_ip, htons(forward_port));
            
            if(ret != 0) {
                return KERN_FAILURE;
            }
            else 
                return KERN_SUCCESS;
        }
        case REDIRECTNKE_UPDATE_SETTINGS:
        {
#ifdef DEBUG
            log("ctl_set Update Settings");
#endif
            void* tmp = data;
            
            log_redirected_packets = *(boolean_t*)tmp;
            tmp += sizeof(boolean_t);
            log_other_packets = *(boolean_t*)tmp;
            
            return KERN_SUCCESS;
        }
        default:
#ifdef DEBUG
            log("ctl_set unknown opt %d", opt);
#endif
            return ENOTSUP;
    }
    
#ifdef DEBUG
    log("Leaving ctl_set");
#endif
    
    return 0;
}

static struct ipf_filter g_ip_filter = { 
    NULL,
    BUNDLEID,
    filter_input,
    filter_output,
    filter_detach
}; 

static struct kern_ctl_reg g_kern_ctl_rel = {
    KERNCTLID,
    0,
    0,
    CTL_FLAG_PRIVILEGED,
    0,
    0,
    ctl_connect,
    ctl_disconnect,
    NULL,
    ctl_set,
    ctl_get
};

kern_return_t RedirectNKE_start (kmod_info_t * ki, void * d) {
    
    log("Network extension loaded");
    
    int result;
    
    TAILQ_INIT(&g_redirection_list);
    TAILQ_INIT(&g_rule_list);
    
#if DEBUG
    log("Allocating OSMalloc Tag");
#endif
    g_osm_tag = OSMalloc_Tagalloc(BUNDLEID, OSMT_DEFAULT);
    if (!g_osm_tag)
        goto bail;
    
#if DEBUG
    log("Creating mutex group");
#endif
    /* allocate mutex group and a mutex to protect global data. */
    g_mutex_group = lck_grp_alloc_init(BUNDLEID, LCK_GRP_ATTR_NULL);
    if (!g_mutex_group)
        goto bail;
    
#if DEBUG
    log("Creating mutex");
#endif
    
    g_mutex = lck_mtx_alloc_init(g_mutex_group, LCK_ATTR_NULL);
    if (!g_mutex)
        goto bail;
    
#if DEBUG
    log("Registering filter");
#endif
    
    result = ipf_addv4(&g_ip_filter, &g_filter_ref);
    
#if DEBUG
    log("ipf_addv4 returned %d", result);
#endif
    
    if (result != KERN_SUCCESS)
        goto bail;
    
#if DEBUG
    log("Registering control socket");
#endif
    
    result = ctl_register(&g_kern_ctl_rel, &g_ctl_ref);
    
    if(result != KERN_SUCCESS)
        goto bail;
    
    getmicrotime(&g_last_clean_and_stats);
    
    g_filter_registered = TRUE;
    g_connected_clients = 0;
    
#if DEBUG
    log("_start leaving");
#endif
    
    return result;
bail:
    
#if DEBUG
    log("_start bailing");
#endif
    
    if (g_mutex)
    {
        lck_mtx_free(g_mutex, g_mutex_group);
        g_mutex = NULL;
    }
    if (g_mutex_group)
    {
        lck_grp_free(g_mutex_group);
        g_mutex_group = NULL;
    }
    if (g_osm_tag)
    {
        OSMalloc_Tagfree(g_osm_tag);
        g_osm_tag = NULL;
    }
    
    return KERN_FAILURE;
}


kern_return_t RedirectNKE_stop (kmod_info_t * ki, void * d) {
    
    
    log("Network extension stopping");
    
    
    if(g_connected_clients > 0)
    {
        log("Cannot stop: there are %d control sockets connected", g_connected_clients);
        return KERN_FAILURE;
    }
    
    if (g_filter_registered)
    {
#if DEBUG
        int err = ipf_remove(g_filter_ref);
        log("ipf_remove returned %d", err);
#endif
        g_filter_registered = FALSE;
    }
    
    /* We need to ensure filter is detached before we return */
    if (!g_filter_detached) {
#if DEBUG
        log("Filter not detached, returning EAGAIN");
#endif
        return EAGAIN; // Try unloading again.
    }
    
    
#if DEBUG
    log("Removing control socket");
#endif
    
    ctl_deregister(g_ctl_ref);
    
#if DEBUG
    log("Locking mutex");
#endif
    
    lck_mtx_lock(g_mutex);
    
#if DEBUG
    log("Locked mutex");
#endif
    
    /* cleanup */
    cleanRules();
    cleanRedirection();
    
#if DEBUG
    log("Unlocking mutex");
#endif
    
    lck_mtx_unlock(g_mutex);
    
#if DEBUG
    log("Unlocked mutex");
#endif  
    
    lck_mtx_free(g_mutex, g_mutex_group);
    lck_grp_free(g_mutex_group);
    g_mutex = NULL;
    g_mutex_group = NULL;
    
    OSMalloc_Tagfree(g_osm_tag);
    g_osm_tag = NULL;
    
    
#if DEBUG
    log("_stop returning KERN_SUCCESS");
#endif
    
    return KERN_SUCCESS;
}
