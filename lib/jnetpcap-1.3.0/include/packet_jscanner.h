/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_jscanner_h
#define _Included_jnetpcap_packet_jscanner_h
#ifdef __cplusplus

#include <stdint.h>

#include "export.h"
#include "org_jnetpcap_packet_JScanner.h"
#include "org_jnetpcap_packet_JRegistry.h"
#include "org_jnetpcap_packet_JPacket_State.h"
#include "org_jnetpcap_packet_JHeader_State.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "packet_flow.h"
#include "util_debug.h"

/******************************
 ******************************
 */
#define JREGISTRY org_jnetpcap_packet_JRegistry_
#define MAX_ID_COUNT 					org_jnetpcap_packet_JRegistry_MAX_ID_COUNT
#define FLAG_OVERRIDE_LENGTH 			org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_LENGTH
#define FLAG_OVERRIDE_BINDING 			org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_BINDING
#define FLAG_HEURISTIC_BINDING 			org_jnetpcap_packet_JRegistry_FLAG_HEURISTIC_BINDING
#define FLAG_HEURISTIC_PRE_BINDING 		org_jnetpcap_packet_JRegistry_FLAG_HEURISTIC_PRE_BINDING

#define JSCANNER org_jnetpcap_packet_JScanner_
#define MAX_ENTRY_COUNT 				org_jnetpcap_packet_JScanner_MAX_ENTRY_COUNT

#define JPROTOCOL org_jnetpcap_protocol_JProtocol_
#define PAYLOAD_ID 						org_jnetpcap_protocol_JProtocol_PAYLOAD_ID

#define JPACKET org_jnetpcap_packet_JPacket_State_
#define PACKET_FLAG_TRUNCATED 			org_jnetpcap_packet_JPacket_State_FLAG_TRUNCATED

#define JHEADER org_jnetpcap_packet_JHeader_State_
#define HEADER_FLAG_PREFIX_TRUNCATED 		org_jnetpcap_packet_JHeader_State_FLAG_PREFIX_TRUNCATED
#define HEADER_FLAG_HEADER_TRUNCATED 		org_jnetpcap_packet_JHeader_State_FLAG_HEADER_TRUNCATED
#define HEADER_FLAG_PAYLOAD_TRUNCATED 		org_jnetpcap_packet_JHeader_State_FLAG_PAYLOAD_TRUNCATED
#define HEADER_FLAG_GAP_TRUNCATED 			org_jnetpcap_packet_JHeader_State_FLAG_GAP_TRUNCATED
#define HEADER_FLAG_POSTFIX_TRUNCATED 		org_jnetpcap_packet_JHeader_State_FLAG_POSTFIX_TRUNCATED
#define HEADER_FLAG_HEURISTIC_BINDING 		org_jnetpcap_packet_JHeader_State_FLAG_HEURISTIC_BINDING
#define HEADER_FLAG_CRC_PERFORMED 			org_jnetpcap_packet_JHeader_State_FLAG_CRC_PERFORMED
#define HEADER_FLAG_CRC_INVALID 			org_jnetpcap_packet_JHeader_State_FLAG_CRC_INVALID
#define HEADER_FLAG_FRAGMENTED 				org_jnetpcap_packet_JHeader_State_FLAG_HEADER_FRAGMENTED
#define HEADER_FLAG_SUBHEADERS_DISSECTED 	org_jnetpcap_packet_JHeader_State_FLAG_SUBHEADERS_DISSECTED
#define HEADER_FLAG_FIELDS_DISSECTED 		org_jnetpcap_packet_JHeader_State_FLAG_FIELDS_DISSECTED
#define HEADER_FLAG_IGNORE_BOUNDS			org_jnetpcap_packet_JHeader_State_FLAG_IGNORE_BOUNDS
#define HEADER_FLAG_HEADER_FRAGMENTED		org_jnetpcap_packet_JHeader_State_FLAG_HEADER_FRAGMENTED

/* Cumulative flags. Flags which are passed to subsequent encapsulated headers */
#define CUMULATIVE_FLAG_HEADER_FRAGMENTED \
	HEADER_FLAG_HEADER_FRAGMENTED | \
	HEADER_FLAG_IGNORE_BOUNDS

#define CUMULATIVE_FLAG_MASK CUMULATIVE_FLAG_HEADER_FRAGMENTED

#define INVALID PAYLOAD_ID

#define ACCESS(offset) if (is_accessible(scan, offset) == FALSE) return;


/******************************
 ******************************
 */
extern jclass jheaderScannerClass;

extern 	jmethodID scanHeaderMID;


/******************************
 ******************************
 */

// Forward references
struct scanner_t;
struct packet_state_t;
struct header_t;
struct scan_t;
struct dissect_t;

/*
 * Array of function pointers. These functions perform a per protocol scan
 * and return the next header. They also return the length of the header in
 * the supplied int pointer.
 */
void init_native_protocols();
typedef void (*native_protocol_func_t)(scan_t *scan);
typedef int (*native_validate_func_t)(scan_t *scan);
typedef void (*native_dissect_func_t)(dissect_t *dissect);
typedef void (*native_debug_func_t)(void *hdr);

extern native_protocol_func_t native_protocols[];
extern native_validate_func_t native_heuristics[MAX_ID_COUNT][MAX_ID_COUNT];
extern native_debug_func_t native_debug[];
extern const char *native_protocol_names[];

void callJavaHeaderScanner(scan_t *scan);
void record_header(scan_t *scan);
void adjustForTruncatedPacket(scan_t *scan);


extern char str_buf[1024];



/**
 * Experimental structures to be used in header dissection, that is complete header
 * structural breakdown. dissected_t records individual field information within
 * the header. Also record information about sub-headers which are within the
 * main header. Structure within the header is bitbased not byte based since
 * any field within a header might occur at any particular bit offset into the
 * header.
 * 
 * Dissectors only record information about non-static fields headers. Static
 * fields don't need description since they are always at the same offset and
 * length.
 */

//#define DISSECTOR_TYPE_FIELD	1
//#define DISSECTOR_TYPE_HEADER	2
//
#define DISSECTOR_FLAG_FIELDS	0x0001
#define DISSECTOR_FLAG_HEADERS	0x0002
//
//typedef union dfield_t {
//	uint8_t		dt_id;
//	uint16_t	dt_flags;
//	uint16_t	dt_offset;		// in bits
//	uint16_t	dt_length;		// in bits
//} dfield_t;

/*
 * Structure maintains state for the duration of a header dissection.
 */
typedef struct dissect_t {
	JNIEnv *env;
	
	packet_state_t 	*d_packet;
	header_t 		*d_header;
	scanner_t 		*d_scanner;
	
	uint8_t			*d_buf;
	int   			d_buf_len;  
	int 			d_offset;
} dissect_t;

/*
 * Structure maintains state for the duration of the scan in progress
 * 
 * The structure keeps track of the packet buffer and 3 types of lengths. 
 * 1) mem_len is the actual total length of the buffer in memory
 * 2) wire_len is the length of the original packet when it was captured before
 *    it was truncated
 * 3) buf_len is the runtime/effectual length of the buffer used by the scanner
 *    methods. This length may shrink if a protocol uses postfix for padding
 *    or some kind of trailer. The buf_len field is reduced by the scanner
 *    for that header by the appropriate amount so that next header doesn't 
 *    consider the previous header's postfix as valid part of the packet it
 *    needs to decode.
 */
typedef struct scan_t {
	JNIEnv *env;
	jobject jscanner;
	jobject jpacket;
	jobject jscan; // This structure as a java object
	scanner_t *scanner;
	
	packet_state_t *packet;
	header_t *header;
	char *buf;
	int   buf_len;  
	int   wire_len;
	int   mem_len;
	int offset;
	int length;
	int id;
	int next_id;
	int flags;
	
	int hdr_prefix;
	int hdr_gap;
	int hdr_payload;
	int hdr_postfix;
	int hdr_flags;
	int is_recorded;
	
	int hdr_count;
	int hdr_index;
} scan_t;

#define SCAN_IS_FRAGMENT(scan) (scan->flags & HEADER_FLAG_FRAGMENTED)
#define SCAN_IGNORE_BOUNDS(scan) (scan->flags & HEADER_FLAG_IGNORE_BOUNDS)
#define SCAN_IS_PREFIX_TRUNCATED(scan) (scan->flags & HEADER_FLAG_PREFIX_TRUNCATED)
#define SCAN_IS_HEADER_TRUNCATED(scan) (scan->flags & HEADER_FLAG_HEADER_TRUNCATED)
#define SCAN_IS_GAP_TRUNCATED(scan) (scan->flags & HEADER_FLAG_GAP_TRUNCATED)
#define SCAN_IS_PAYLOAD_TRUNCATED(scan) (scan->flags & HEADER_FLAG_PAYLOAD_TRUNCATED)
#define SCAN_IS_POSTFIX_TRUNCATED(scan) (scan->flags & HEADER_FLAG_POSTFIX_TRUNCATED)

/*
 * Each header "record" may have the following physical structure:
 * +-------------------------------------------+
 * | prefix | header | gap | payload | postfix |
 * +-------------------------------------------+
 * 
 * Offset points at the start of the header, not the prefix. In order to calculate
 * the exact start of the record, you must subtract the prefix length from the 
 * offset as follows:
 * 
 * prefix_offset = hdr_offset - hdr_prefix;
 * 
 * To calculate the offset of the start of the payload:
 * 
 * payload_offset = hdr_offset + hdr_length + hdr_gap;
 * 
 * To calculate the offset of the start of the postfix
 * 
 * postfix_offset = hdr_offset + hdr_length + hdr_gap + hdr_payload;
 * 
 * To calculate the end of the header record:
 * 
 * end_offset = hdr_offset + hdr_length + hdr_gap + hdr_payload + hdr_postifx;
 * 
 * Note that most of the time the fields hdr_prefix, hdr_gap and hdr_postfix
 * will be zero, but this structure does allow a more complex headers in a 
 * frame to exist. Some protocols have prefixes such Ethernet2 frames on BSD 
 * systems and a trailer (represented as a postfix) which may contains padding,
 * CRC counters etc. Rtp header for example utilizes padding after its payload
 * and so do many other protocols. As of right now, the author is not aware of
 * any protocols utilizing an inter header-to-payload gap, which is another way
 * of saying a header-padding. None the less, the structure for gap is 
 * represented here for future compatibility.
 */
typedef struct header_t {
	uint8_t  hdr_id;         // header ID
	
	uint8_t  hdr_prefix;     // length of the prefix (preamble) before the header 
	uint8_t  hdr_gap;        // length of the gap between header and payload
	uint16_t  hdr_flags;      // flags for this header
	uint16_t hdr_postfix;    // length of the postfix (trailer) after the payload
	uint32_t hdr_offset;     // offset into the packet_t->data buffer
	uint32_t hdr_length;     // length of the header in packet_t->data buffer
	uint32_t hdr_payload;    // length of the payload
	
	uint8_t	  hdr_subcount;	 // number of sub-headers
	header_t  *hdr_subheader;   // Index of the first subheader in packet_t
	
	jobject  hdr_analysis;   // Java JAnalysis based object if not null
} header_t;

typedef struct packet_state_t {
	flow_key_t pkt_flow_key; // Flow key calculated for this packet, must be first
	uint8_t pkt_flags;       // flags for this packet
	jobject pkt_analysis;    // Java JAnalysis based object if not null
	uint64_t pkt_frame_num;  // Packet's frame number assigned by scanner
	uint64_t pkt_header_map; // bit map of presence of headers
	
	uint32_t pkt_wirelen;    // Original packet size

	int8_t pkt_header_count; // total number of main headers found
	header_t pkt_headers[];  // One per header + 1 more for payload
	
	int8_t pkt_subheader_count;  // total number of sub headers found
	header_t pkt_subheaders[];  // One per header + 1 more for payload
} packet_state_t;

typedef struct scanner_t {
	int32_t sc_len; // bytes allocated for sc_packets buffer
	
	uint64_t sc_cur_frame_num; // Current frame number

	uint32_t sc_flags[MAX_ID_COUNT]; // protocol flags
//	uint64_t sc_native_header_scanner_map;  // java binding map
	
	jobject sc_jscan; // Java JScan structure for interacting with java space

	jobject sc_java_header_scanners[MAX_ID_COUNT]; // java scanners
	
	/*
	 * A per scanner instance table that can be populated with native and
	 * java scanners at the same time.
	 */
	native_protocol_func_t sc_scan_table[MAX_ID_COUNT];
	native_validate_func_t sc_heuristics_table[MAX_ID_COUNT][MAX_ID_COUNT]; // Huristic

	
	/* Packet and main header ring-buffer */
	int			 	sc_offset; // offset into sc_packets for next packet
	packet_state_t *sc_packet; 	// ptr into scanner_t where the first packet begins
	
	/* Sub-header ring buffer */
	int			sc_sublen;		// Length of the sub-header ring-buffer
	int 		sc_subindex; 	// sub-header offset
	header_t 	*sc_subheader; // ptr where first sub-headers begin
	
	int			sc_heap_len;
	int			sc_heap_offset;
	jobject		sc_heap_owner;
	uint8_t		*sc_heap;
	
} scanner_t;



/******************************
 ******************************
 */

int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner, packet_state_t *packet,
		int first_id, char *buf, int buf_length, uint32_t wirelen);

int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate, scanner_t *scanner, int first_id, char *buf,
		int buf_length, uint32_t wirelen);

int scanJavaBinding(scan_t *scan);

uint64_t toUlong64(JNIEnv *env, jintArray ja);

jint findHeaderById(packet_state_t *packet, jint id, jint instance);

const char *id2str(int id);

int validate(int id, scan_t *);
int validate_next(int id, scan_t *);

/****
 * Temporarily backed out of C++ Debug class and G++ compiler
 *
extern Debug scanner_logger;
extern Debug protocol_logger;
*****/
/**
 * Checks and calculates if there is enough data in the
 * buffer to access entire header, if not the header's
 * TRUNCATE flag is set and header's length set to wire_len.
 *
 * scan->length is the input and output with theoretical header length.
 * scan->wire_len is the input with actual buffer length.
 * scan->hdr_flags output with TRUNCATED flag set.
 */
int truncate_header(scan_t *scan);

int is_accessible(scan_t *scan, int offset);



#endif
#endif
