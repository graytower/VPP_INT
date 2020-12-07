#ifndef included_vnet_ip4_inwt_h
#define included_vnet_ip4_inwt_h

#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt_packet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vlib/log.h>

typedef struct
{
	u8 *rewrite_sr;
	u8 *rewrite_int;
} ip4_inwt_policy_t;

typedef struct
{
	ethernet_header_t l2_header;
	ip4_header_t l3_header;
} __attribute__ ((packed)) ip4_inwt_template_header_t;

typedef struct
{
	ip4_inwt_policy_t *inwt_policies;


	/** Template used to generate INWT probe packets. */
	vlib_packet_template_t inwt_probe_packet_template;
	
	/** convenience */
	vlib_main_t *vlib_main;
	vnet_main_t *vnet_main;

	/** log class */
	vlib_log_class_t log_class;
} ip4_inwt_main_t;

extern ip4_inwt_main_t ip4_inwt_main;

extern vlib_node_registration_t inwt_probe_packet_generation_node;
extern vlib_node_registration_t inwt_sr_forwarding_node;

#endif /* included_vnet_ip4_inwt_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
