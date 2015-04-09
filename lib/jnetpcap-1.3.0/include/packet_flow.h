/* Header for analysis_flow utility methods */

#ifndef _Included_packet_flow_h
#define _Included_packet_flow_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include <stdint.h>
#include <stdint.h>
#include "export.h"
	
#include <jni.h>
#include "org_jnetpcap_packet_JFlowKey.h"
	
#define FLOW_KEY_PAIR_COUNT org_jnetpcap_packet_JFlowKey_FLOW_KEY_PAIR_COUNT

struct scan_t; // Forward reference

/*
 * Flow key is made up of several key pairs. In order for a flow key to be
 * equal to another flow key, all the pair values must match. The flow pairs
 * can be bi-directional. If uni directional flag is not set, it means that the
 * second array of pairs is also in use and the values there are exact pair
 * reversal of the first array of pairs.
 */
typedef struct flow_key_t {
	uint64_t header_map; // bitmap of header IDs part of this flowkey
	uint32_t hash; // Hashcode
#define FLOW_KEY_FLAG_REVERSABLE_PAIRS org_jnetpcap_packet_JFlowKey_FLAG_REVERSABLE
	uint16_t flags; // flags
	uint16_t pair_count;  // number of pairs upto FLOW_KEY_PAIR_COUNT
	uint8_t id[FLOW_KEY_PAIR_COUNT];
	uint32_t forward_pair[FLOW_KEY_PAIR_COUNT][2];
	uint32_t reverse_pair[FLOW_KEY_PAIR_COUNT][2];
} flow_key_t;

/**
 * Based on the first part of the key, it sets the second part of the key
 * using reversed direction values for each pair. flow_key_t->pair[2] is a
 * multi-dimensional array that has 2 sets of key pairs. [0] for forward keys
 * and [1] for reverse direction keys.
 */
void flow_key_init(flow_key_t *key, int id);

void process_flow_key(scan_t *scan);


#ifdef __cplusplus
}
#endif
#endif
