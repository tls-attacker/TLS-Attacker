/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id: in_cksum.h 12117 2004-09-28 00:06:32Z guy $
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdio.h>
#include <stdint.h>
#include <jni.h>

typedef struct {
	const uint8_t *ptr;
	int	len;
} vec_t;

extern uint16_t in_cksum(const vec_t *vec, int veclen);
extern uint16_t in_cksum_shouldbe(uint16_t sum, uint16_t computed_sum);

typedef union {
	uint8_t c[2];
	uint16_t s;
} pad_t; 

extern int in_checksum_pad_to_even(
		vec_t *vec,
		int veclen,
		pad_t *pad);

extern int in_checksum_skip_crc16_field(
		const uint8_t *buf, // Buffer ptr
		vec_t *vec, 
		int len,
		int crc_offset);

extern int in_checksum_add_ip_pseudo_header(
		const uint8_t *buf, 
		vec_t *vec, 
		int type, 
		int len,
		uint32_t phdr[2]);

extern uint16_t  psuedo_ip4_tcp(
		JNIEnv *env, 
		const uint8_t *mem, 
		size_t size, 
		jint ip4, 
		jint tcp);

uint16_t  psuedo_ip6_tcp(
		JNIEnv *env, 
		const uint8_t *mem, 
		size_t size, 
		jint ip6, 
		jint tcp);


#ifdef __cplusplus
}
#endif /* __cplusplus */
