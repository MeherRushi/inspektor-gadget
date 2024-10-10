// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation


#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file and linux/pkt_cls.h
because of redeclration conflicts with
vmlinux.h */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/


#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7


#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>


/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct events_map_key{
	struct gadget_l4endpoint_t dst;
	/* another field to indicate source or destination */
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t filter_ipv4;
    gadget_counter__u32 drop_cnt;
	bool ingress;
	bool egress;

	gadget_mntns_id mntns_id;
	gadget_netns_id netns_id;

	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,struct events_map_key);	// The key is going to be <dst addr,port> pair
	__type(value,struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter,events_map);


// we use the following variables as parameters
const volatile __u8 a = 0;
const volatile __u8 b = 0;
const volatile __u8 c = 0;
const volatile __u8 d = 0;
const volatile __u16 port = 0;
const volatile __u32 loss_percentage = 100;
const volatile bool filter_tcp = true;		/* This is a boolean flag to enable filtering of TCP packets */
const volatile bool filter_udp = true;		/* This is a boolean flag to enable filtering of UDP packets */
const volatile bool ingress = false;		/* This is a boolean flag to enable filtering of ingress packets */
const volatile bool egress = true;			/* This is a boolean flag to enable filtering of egress packets */

GADGET_PARAM(a);
GADGET_PARAM(b);
GADGET_PARAM(c);
GADGET_PARAM(d);
GADGET_PARAM(port);
GADGET_PARAM(loss_percentage);
GADGET_PARAM(filter_tcp);
GADGET_PARAM(filter_udp);
GADGET_PARAM(ingress);
GADGET_PARAM(egress);

/* 
Let's take the ip to be in the 
format of -a 127 -b 0 -c 0 -d 1 -port 443
which translates to 127.0.0.1:443 
*/

/* This function drops packets based on independent (Bernoulli) probability model 
where each packet is dropped with an independent probabilty for dropping packets */
static int rand_pkt_drop_map_update(struct event *event, struct events_map_key *key,
									struct sockets_key *sockets_key_for_md)
{
    __u32 rand_num = bpf_get_prandom_u32();									// Get a random 32-bit unsigned integer
    // Set the threshold using the loss_percentage
    volatile __u64 threshold = (volatile __u64)(
								(volatile __u64)loss_percentage 
								* (__u64)0xFFFFFFFF
								)/100;										// loss_percentage% of UINT32_MAX
	
	struct event *event_map_val  = bpf_map_lookup_elem(&events_map,key);   /* The events which are stored in the events_map */
	
	if (rand_num <= (u32)threshold)											// Run the code only if the random number is less than the threshold
	{
		if(!event_map_val){
			event->drop_cnt = 1;
			/* Data collection using the socket enricher, we use the key from the map
			to collect information regarding pid, mntns_id, tid, ppid etc */
			sockets_key_for_md->port = key->dst.port;
			struct sockets_value *skb_val = bpf_map_lookup_elem(&gadget_sockets, sockets_key_for_md);
			if (skb_val != NULL)
			{
				event->mntns_id = skb_val->mntns;
				event->pid = skb_val->pid_tgid >> 32;
				event->tid = (__u32)skb_val->pid_tgid;
				event->ppid = skb_val->ppid;
				__builtin_memcpy(&event->comm, skb_val->task, sizeof(event->comm));
				__builtin_memcpy(&event->pcomm, skb_val->ptask, sizeof(event->pcomm));
				event->uid = (__u32)skb_val->uid_gid;
				event->gid = (__u32)(skb_val->uid_gid >> 32);
			}
			bpf_map_update_elem(&events_map,key,event,BPF_NOEXIST);
		} 
		else
		{
			// Increment the the value of drop count by 1. 
			// We use sync fetch and add which is an atomic addition operation
			__sync_fetch_and_add(&event_map_val->drop_cnt, 1);
			bpf_map_update_elem(&events_map,key,event_map_val,BPF_EXIST);
		}
		return TC_ACT_SHOT;			
	} 
	return TC_ACT_OK;
}

static __always_inline void swap_src_dst(struct event *event, struct events_map_key *key){
	struct gadget_l4endpoint_t temp;
	temp = event->src;
	event->src = key->dst;
	key->dst = temp;
}

static __always_inline void read_ipv6_address(struct event *event, struct events_map_key *key, struct ipv6hdr *ip6h ){
	bpf_probe_read_kernel(event->src.addr_raw.v6, sizeof(event->src.addr_raw.v6), ip6h->saddr.in6_u.u6_addr8);
	bpf_probe_read_kernel(key->dst.addr_raw.v6, sizeof(key->dst.addr_raw.v6), ip6h->daddr.in6_u.u6_addr8);
}

static __always_inline int packet_drop(struct __sk_buff *skb){
		
	struct events_map_key key;						/* This is the key for events_map -> being the dst addr,port pair */
	struct sockets_key sockets_key_for_md; 			/* This is for socket enrichement map */

	struct gadget_l4endpoint_t filter_ip;			/* filter ip - ideally should be a parameter from userspace */

	struct event event;								/* The sturct to store the information regarding the event */						

	event.egress = egress;
	event.ingress = ingress;
	event.netns_id = skb->cb[0]; 					// cb[0] initialized by dispatcher.bpf.c to get the netns
	sockets_key_for_md.netns = event.netns_id;		

    void *data = (void *)(long)skb->data;			
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
	struct iphdr *ip4h ;
	struct ipv6hdr *ip6h ;

    /* Check if the ethernet headers are invalid if so ignore 
	   the packets, else do the further processing	 */
    if ((void *)(eth + 1)> data_end)
    {
		return TC_ACT_OK; 															// Eth headers incomplete - Letting them pass through the without further processing
    }

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) 									// IPv4 Processing
	{
		ip4h = (struct iphdr *)(eth + 1);

		/* Check if the IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end)
		{
			return TC_ACT_OK;
		}

		event.src.addr_raw.v4 = ip4h->saddr;
		key.dst.addr_raw.v4 = ip4h->daddr;
		event.src.version = key.dst.version = 4;
		sockets_key_for_md.family = SE_AF_INET;

		if (filter_tcp == true && ip4h->protocol == IPPROTO_TCP) 							// Check if packets follow TCP protocol and if we want to drop tcp packets 
		{								
			struct tcphdr *tcph = (struct tcphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;  								// Packet is too short, ignore
			event.src.proto = key.dst.proto = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);										// Extract source and destination ports from the TCP header	
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(tcph->dest);
			else
				key.dst.port = bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip4h->protocol == IPPROTO_UDP )
		{										
			struct udphdr *udph = (struct udphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(udph + 1) > data_end) return TC_ACT_OK;  								// Packet is too short
			event.src.port = bpf_ntohs(udph->source);										// Extract source and destination ports from the UDP header
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(udph->dest);
			else
				key.dst.port = bpf_ntohs(udph->source);
			event.src.proto = key.dst.proto = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else 
		{
			return TC_ACT_OK;
		}
	}	
	else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) 									// IPv6 Processing
	{
		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if the IPv6 headers are invalid */
		if ((void *)(ip6h + 1)  > data_end)
		{
			return TC_ACT_OK;
		}
		event.src.version = key.dst.version = 6;
		sockets_key_for_md.family = SE_AF_INET6;
		
		// Check if packets follow TCP protocol
		if (filter_tcp == true && ip6h->nexthdr == IPPROTO_TCP) 
		{
			read_ipv6_address(&event, &key, ip6h);

			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)  return TC_ACT_OK; 							 // Packet is too short, ignore
			event.src.proto = key.dst.proto = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(tcph->dest);
			else
				key.dst.port = bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip6h->nexthdr == IPPROTO_UDP)
		{
			struct udphdr *udph = (struct udphdr *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)  return TC_ACT_OK;  							 // Packet is too short, ignore
			event.src.port = bpf_ntohs(udph->source);
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(udph->dest);
			else
				key.dst.port = bpf_ntohs(udph->source);
			event.src.proto = key.dst.proto = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else
		{
			return TC_ACT_OK;
		}
	} 
	else
	{
		return TC_ACT_OK;	// Letting them pass through the without further processing
	}
	

	filter_ip.addr_raw.v4 = (a << 24) | (b << 16) | (c << 8) | d;
	filter_ip.port = port;
	if(filter_tcp == true)
		filter_ip.proto = IPPROTO_TCP;
	else
		filter_ip.proto = IPPROTO_UDP;
	filter_ip.version = 4;
	event.filter_ipv4 = filter_ip;
	event.timestamp_raw = bpf_ktime_get_boot_ns();


	/* To cover different cases where the IP and port pair are given */
	// If both IP and port are 0, then drop loss% of all packets
	if(a == 0 && b == 0 && c == 0 && d == 0 && port == 0)
	{
		return rand_pkt_drop_map_update(&event, &key, &sockets_key_for_md);
	} 
	// If the IP is non 0 and port is 0, then drop all packets to any port for that IP
	else if ((a != 0 || b != 0 || c != 0 || d == 0) && port == 0) 
	{
		if(ingress == true && egress == true) 				// Then we drop in case it matches either destination or source
		{
			if(key.dst.addr_raw.v4 == filter_ip.addr_raw.v4 || event.src.addr_raw.v4 == filter_ip.addr_raw.v4)
			{
				rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
				swap_src_dst(&event, &key);
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}	
		else 													// Both ingress and egress being false will not even invoke this function so this else case deals with only either one of them being true
		{
			if(ingress == true)
				swap_src_dst(&event, &key);
			if (key.dst.addr_raw.v4 == filter_ip.addr_raw.v4)
			{
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}
	}
	// If IP is zero and port is non zero, then drop all packets to the port
	else if(a == 0 && b == 0 && c == 0 && d == 0 && port != 0)
	{
		if(ingress == true && egress == true) 				// Then we drop in case it matches either destination or source
		{
			if(key.dst.port == filter_ip.port|| event.src.port == filter_ip.port)
			{
				rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
				swap_src_dst(&event, &key);
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}
		else 													// Both ingress and egress being false will not even invoke this function so this else case deals with only either one of them being true
		{
			if(ingress == true)
				swap_src_dst(&event, &key);
			if(key.dst.port == filter_ip.port)
			{
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}
	}
	// If both are non zero
	else
	{
		if(ingress == true && egress == true) 				// Then we drop in case it matches either destination or source
		{
			if(key.dst.addr_raw.v4 == filter_ip.addr_raw.v4 && key.dst.port == filter_ip.port || event.src.addr_raw.v4 == filter_ip.addr_raw.v4 && event.src.port == filter_ip.port)
			{
				rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
				swap_src_dst(&event, &key);
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}
		else 												// Both ingress and egress being false will not even invoke this function so this else case deals with only either one of them being true
		{
			if(ingress == true)
				swap_src_dst(&event, &key);
			if(key.dst.addr_raw.v4 == filter_ip.addr_raw.v4 && key.dst.port == filter_ip.port)
			{
				return rand_pkt_drop_map_update(&event, &key,&sockets_key_for_md);
			}
		}
	}
	
	return TC_ACT_OK;
}

SEC("classifier/egress/drop")
int egress_pkt_drop(struct __sk_buff *skb){
	if(egress == true) 
		return packet_drop(skb);
	else
		return TC_ACT_OK;
}

/* Extremly similar to egress */
SEC("classifier/ingress/drop")
int ingress_pkt_drop(struct __sk_buff *skb){
	
	if(ingress == true)				
		return packet_drop(skb);
	else
		return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";	