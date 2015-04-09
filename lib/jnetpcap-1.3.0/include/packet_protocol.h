/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_protocol_h
#define _Included_jnetpcap_packet_protocol_h
#ifdef __cplusplus

#include <stdint.h>

#include "export.h"
#include <jni.h>
#include "nio_jbuffer.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "org_jnetpcap_packet_JScan.h"

#define END_OF_HEADERS   org_jnetpcap_packet_JScan_END_OF_HEADERS_ID
#define ETHERNET_ID      org_jnetpcap_protocol_JProtocol_ETHERNET_ID
#define TCP_ID           org_jnetpcap_protocol_JProtocol_TCP_ID
#define UDP_ID           org_jnetpcap_protocol_JProtocol_UDP_ID
#define IEEE_802DOT3_ID  org_jnetpcap_protocol_JProtocol_IEEE_802DOT3_ID
#define IEEE_802DOT2_ID  org_jnetpcap_protocol_JProtocol_IEEE_802DOT2_ID
#define IEEE_SNAP_ID     org_jnetpcap_protocol_JProtocol_IEEE_SNAP_ID
#define IP4_ID           org_jnetpcap_protocol_JProtocol_IP4_ID
#define IP6_ID           org_jnetpcap_protocol_JProtocol_IP6_ID
#define IEEE_802DOT1Q_ID org_jnetpcap_protocol_JProtocol_IEEE_802DOT1Q_ID
#define L2TP_ID          org_jnetpcap_protocol_JProtocol_L2TP_ID
#define PPP_ID           org_jnetpcap_protocol_JProtocol_PPP_ID
#define ICMP_ID          org_jnetpcap_protocol_JProtocol_ICMP_ID
#define HTTP_ID          org_jnetpcap_protocol_JProtocol_HTTP_ID
#define HTML_ID          org_jnetpcap_protocol_JProtocol_HTML_ID
#define ARP_ID           org_jnetpcap_protocol_JProtocol_ARP_ID
#define SIP_ID           org_jnetpcap_protocol_JProtocol_SIP_ID
#define SDP_ID           org_jnetpcap_protocol_JProtocol_SDP_ID
#define RTP_ID           org_jnetpcap_protocol_JProtocol_RTP_ID
#define SLL_ID           org_jnetpcap_protocol_JProtocol_SLL_ID
#define WEB_IMAGE_ID        org_jnetpcap_protocol_JProtocol_WEB_IMAGE_ID


/*
 * Linux Socket Cooked Capture header - a pseudo header as DL substitute
 */
#define SLL_LEN	16		          // total header length
#define SLL_ADDR_LEN	8		      // length of address field

typedef struct sll_t {
	u_int16_t	sll_pkttype;	          // packet type
	u_int16_t	sll_hatype;	            // link-layer address type
	u_int16_t	sll_halen;	            // link-layer address length
	u_int8_t	sll_addr[SLL_ADDR_LEN];	// link-layer address
	u_int16_t	sll_protocol;         	// protocol
} sll_t;

/*
 * Realtime Transfer Protocol and extension
 */
#define RTP_LENGTH	12
#define RTPX_LENGTH	4

typedef struct rtpx_t {
	
	uint16_t	rtpx_profile; 	// Profile specific
	uint16_t	rtpx_len;		// Length of extension header
	
} rtpx_t;

typedef struct rtp_t {

#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t 	rtp_cc:4;
	uint8_t 	rtp_ext:1;
	uint8_t 	rtp_pad:1;
	uint8_t		rtp_ver:2;
	
	uint8_t		rtp_type:7;
	uint8_t		rtp_marker:1;
	
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		rtp_ver:2;
	uint8_t 	rtp_pad:1;
	uint8_t 	rtp_ext:1;
	uint8_t 	rtp_cc:4;
	
	uint8_t		rtp_marker:1;
	uint8_t		rtp_type:7;
	
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	
	uint16_t	rtp_seq;
	uint32_t	rtp_ts;
	uint32_t	rtp_ssrc;


} rtp_t;


/*
 * Address Resulution Protocol
 */
typedef struct arp_t {
	uint16_t htype;
	uint16_t ptype;
	uint8_t  hlen;
	uint8_t  plen;
} arp_t;


/*
 * Internet Control Message Protocol
 */
typedef struct icmp_t {
	uint8_t type;
	uint8_t code;
	uint16_t crc;

} icmp_t;

/*
 * Point to Point Protocol
 */
typedef struct ppp_t {
	uint8_t addr;
	uint8_t control;
	uint16_t protocol;
} ppt_t;

/*
 * Layer 2 tunneling protocol
 */
typedef struct l2tp_t {
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t p :1;
	uint16_t o :1;
	uint16_t res2 :1;
	uint16_t s :1;
	uint16_t res1 :2;
	uint16_t l :1;
	uint16_t t :1;
	uint16_t version :4;
	uint16_t res3 :4;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t t:1;
	uint16_t l:1;
	uint16_t res1:2;
	uint16_t s:1;
	uint16_t res2:1;
	uint16_t o:1;
	uint16_t p:1;
	uint16_t res3:4;
	uint16_t version:4;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

} l2tp_t;

/*
 * IEEE 802.1q VLAN header
 */
typedef struct vlan_t {
	uint16_t priority :3;
	uint16_t cfi :1;
	uint16_t id :12;

	uint16_t type;
} vlan_t;

/**
 * SNAP IEEE
 */
typedef union snap_t {
	uint32_t oui :24;
	struct {
		uint16_t reserved[1];
		uint16_t pid;
	};
} snap_t;

/**
 * LLC IEEE802.2
 */
typedef struct llc_t {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control;
	union {
		uint8_t info;
	} ucontrol;
} llc_t;

/**
 * UDP structure
 */
typedef struct udp_t {
	uint16_t sport;
	uint16_t dport;
	uint16_t length;
	uint16_t checksum;

} udp_t;

/**
 * TCP structure
 */
typedef struct tcp_t {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1 :4;
	uint16_t doff :4;
	uint16_t fin :1;
	uint16_t syn :1;
	uint16_t rst :1;
	uint16_t psh :1;
	uint16_t ack :1;
	uint16_t urg :1;
	uint16_t res2 :2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} tcp_t;

#define PROTO_ETHERNET_HEADER_LENGTH 14
#define PROTO_802_3_MAX_LEN 0x600

/**
 * Ethernet 2 structure
 */
typedef struct ethernet_t {
	uint8_t dhost[6]; /* destination eth addr */
	uint8_t shost[6]; /* destination eth addr */
	uint16_t type; /* destination eth addr */
} ethernet_t;

/**
 * IP v6 structure
 * RFC 1883
 */
typedef struct ip6 {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, 4 bits class */
	} ip6_ctlun;
	uint8_t ip6_src[16];	/* source address */
	uint8_t ip6_dst[16];	/* destination address */
} ip6_t;

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IP6_HEADER_LENGTH 40

#define IP6_OPT_HOP_BY_HOP 		0
#define IP6_OPT_DEST_OPTIONS	60
#define IP6_OPT_ROUTING_HEADER	43
#define IP6_OPT_FRAGMENT_HEADER	44
#define IP6_OPT_AUTH_HEADER		51
#define IP6_OPT_SECURITY_HEADER	50
#define IP6_OPT_MOBILITY_HEADER	135
#define IP6_OPT_NO_NEXT_HEADER	59

/**
 * IP v4 structure
 */
typedef struct ip4 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl :4;
	unsigned int version :4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off; // flags=3 bits, offset=13 bits
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
} ip4_t;

#define IP4_FLAGS_MASK 0xE000
#define IP4_FRAG_OFF_MASK ~IP4_FLAGS_MASK
#define IP4_FLAG_MF 0x2000
#define IP4_FLAG_DF 0x4000
#define IP4_FLAG_RESERVED 0x8000


/****************************************************************
 * **************************************************************
 * 
 * Scanner's native and java per protocol prototypes
 * 
 * **************************************************************
 ****************************************************************/

int lookup_ethertype(uint16_t type);
//
//void scan_ethernet (scan_t *scan);
//void scan_ip4      (scan_t *scan);


#endif
#endif
