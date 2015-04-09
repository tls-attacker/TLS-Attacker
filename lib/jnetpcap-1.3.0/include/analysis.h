/* Header for analysis_flow utility methods */

#ifndef _Included_analysis_h
#define _Included_analysis_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include <stdint.h>
#include <stdint.h>
#include "export.h"
	
#include <jni.h>
#include "org_jnetpcap_packet_analysis_Analysis.h"
#include "org_jnetpcap_packet_analysis_AnalysisUtils.h"

#define ROOT_TYPE org_jnetpcap_analysis_AnalysisUtils_ROOT_TYPE

/*
 * A header for every analysis object
 */
typedef struct analysis_t {
	uint16_t type;
	uint16_t len; // length so we can walk unknown analysis types
} analysis_t;

/*
 * Roots are embeded in packet_state_t and header_state_t objects
 */
typedef struct root_analysis_t {
	uint16_t type; // == ROOT_TYPE
	uint16_t len; // length so we can walk unknown analysis types
	
	analysis_t *child;
};


typedef void (*native_analyzer_func_t)(packet_state_t *packet);
extern native_analyzer_func_t native_analyzers[];

typedef struct analyzer_t {
	
	native_analyzer_func_t analyzers[64][4];
	
} analyzer_t;

#ifdef __cplusplus
}
#endif
#endif
