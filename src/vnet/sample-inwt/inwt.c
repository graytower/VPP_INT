/**
 * @file
 * @brief In-band Network Wide Telemetry initialization
 * 
 */

#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt.h>
#include <vnet/udp/udp.h>
#include <vlib/log.h>

ip4_inwt_main_t ip4_inwt_main;

/**
 * @brief INWT Initialization
 */
clib_error_t *
inwt_init(vlib_main_t * vm)
{
	ip4_inwt_main_t *iim = &ip4_inwt_main;

	/* Registrations */
	udp_register_dst_port (vm, UDP_DST_PORT_inwt,
		 inwt_probe_packet_generation_node.index, /* is_ip4 */ 1);

	ip4_inwt_template_header_t h;
	clib_memset (&h, 0, sizeof (h));
	vlib_packet_template_init (vm, &iim->inwt_probe_packet_template,
		    /* data */  &h,
		    sizeof (h),
		    /* alloc chunk size */ 8,
		    "inwt probe template");

	iim->log_class = vlib_log_register_class ("inwt", 0);

	return 0;
}

VLIB_INIT_FUNCTION (inwt_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
