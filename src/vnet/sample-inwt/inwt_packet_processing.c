#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt.h>
#include <vnet/sample-inwt/inwt_packet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/error.h>

#include <vlib/log.h>

/* Graph arcs */
#define foreach_inwt_forwarding_next     \
_(IP4_LOOKUP, "ip4-lookup")         \
_(ERROR, "error-drop")

typedef enum
{
#define _(s,n) INWT_FORWARDING_NEXT_##s,
  foreach_inwt_forwarding_next
#undef _
    INWT_FORWARDING_N_NEXT,
} inwt_forwarding_next_t;

/* INWT rewrite errors */
#define foreach_inwt_forwarding_error                     \
_(PROTOCOL, "INWT forwarding wrong protocol")       \
_(CODE, "INWT forwarding wrong code flag")          \
_(LENGTH, "INWT forwarding wrong length and pointer")

typedef enum
{
#define _(sym,str) INWT_FORWARDING_ERROR_##sym,
  foreach_inwt_forwarding_error
#undef _
    INWT_FORWARDING_N_ERROR,
} inwt_forwarding_error_t;

static char *inwt_forwarding_error_strings[] = {
#define _(sym,string) string,
  foreach_inwt_forwarding_error
#undef _
};

/*************************** INWT SR FORWARDING graph node ****************************/
/**
 * @brief INWT SR header processing.
 */
static_always_inline void
sr_header_processing(vlib_node_runtime_t * node,
	                 vlib_buffer_t * b0,
	                 ip4_header_t * ip0,
	                 ip4_inwt_ip4option_sr_header_t * sr0,
	                 u32 * next0)
{
	if(sr0->code != 137)
	{
		*next0 = INWT_FORWARDING_NEXT_ERROR;
		b0->error = node->errors[INWT_FORWARDING_ERROR_CODE];
		return;
	}
	if(sr0->length <= sr0->pointer)
	{
		*next0 = INWT_FORWARDING_NEXT_ERROR;
		b0->error = node->errors[INWT_FORWARDING_ERROR_LENGTH];
		return;
	}
	u8 *p0 = 0;
	p0 = ((u8 *) sr0) + sr0->pointer;

	ip0->dst_address.as_u8[0] = p0[0];
	ip0->dst_address.as_u8[1] = p0[1];
	ip0->dst_address.as_u8[2] = p0[2];
	ip0->dst_address.as_u8[3] = p0[3];

	sr0->pointer += 4;

	ip0->checksum = ip4_header_checksum(ip0);

	*next0 = INWT_FORWARDING_NEXT_IP4_LOOKUP;

	return;
}

/**
 * @brief Graph node for inwt sr forwarding.
 */
static uword
inwt_sr_forwarding(vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
	// ip4_inwt_main_t *iim = &ip4_inwt_main;
	u32 n_left_from, next_index, *from, *to_next;

	from = vlib_frame_vector_args (from_frame);
	n_left_from = from_frame->n_vectors;

	next_index = node->cached_next_index;

	// vlib_log_warn(iim->log_class, "enter into inwt sr forwarding node");

	while(n_left_from > 0)
	{
		u32 n_left_to_next;
		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

		while(n_left_from >= 8 && n_left_to_next >= 4)
		{
			u32 bi0, bi1, bi2, bi3;
			vlib_buffer_t *b0, *b1, *b2, *b3;
			ip4_header_t *ip0, *ip1, *ip2, *ip3;
			ip4_inwt_ip4option_sr_header_t *sr0, *sr1, *sr2, *sr3;
			u32 next0, next1, next2, next3;
			next0 = next1 = next2 = next3 = INWT_FORWARDING_NEXT_IP4_LOOKUP;

			/* Prefetch next iteration. */
			{
				vlib_buffer_t *p4, *p5, *p6, *p7;

				p4 = vlib_get_buffer (vm, from[4]);
				p5 = vlib_get_buffer (vm, from[5]);
				p6 = vlib_get_buffer (vm, from[6]);
				p7 = vlib_get_buffer (vm, from[7]);

				/* Prefetch the buffer header and packet for the N+2 loop iteration */
				vlib_prefetch_buffer_header (p4, LOAD);
				vlib_prefetch_buffer_header (p5, LOAD);
				vlib_prefetch_buffer_header (p6, LOAD);
				vlib_prefetch_buffer_header (p7, LOAD);

				CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
				CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
				CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
				CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
			}

			to_next[0] = bi0 = from[0];
			to_next[1] = bi1 = from[1];
			to_next[2] = bi2 = from[2];
			to_next[3] = bi3 = from[3];
			from += 4;
			to_next += 4;
			n_left_from -= 4;
			n_left_to_next -= 4;

			b0 = vlib_get_buffer(vm, bi0);
			b1 = vlib_get_buffer(vm, bi1);
			b2 = vlib_get_buffer(vm, bi2);
			b3 = vlib_get_buffer(vm, bi3);

			ip0 = vlib_buffer_get_current(b0);
			ip1 = vlib_buffer_get_current(b1);
			ip2 = vlib_buffer_get_current(b2);
			ip3 = vlib_buffer_get_current(b3);

			if(PREDICT_TRUE(ip0->protocol == IP_PROTOCOL_IP4_INWT))
			{
				sr0 = (ip4_inwt_ip4option_sr_header_t *) (ip0 + 1);
				sr_header_processing(node, b0, ip0, sr0, &next0);
				// vlib_log_warn(iim->log_class, "inwt sr forwading dst ip: %U",
				// 	format_ip4_address, &ip0->dst_address);
			}
			else
			{
				b0->error = node->errors[INWT_FORWARDING_ERROR_PROTOCOL];
				continue;
			}

			if(PREDICT_TRUE(ip1->protocol == IP_PROTOCOL_IP4_INWT))
			{
				sr1 = (ip4_inwt_ip4option_sr_header_t *) (ip1 + 1);
				sr_header_processing(node, b1, ip1, sr1, &next1);
				// vlib_log_warn(iim->log_class, "inwt sr forwading dst ip: %U",
				// 	format_ip4_address, &ip1->dst_address);
			}
			else
			{
				b1->error = node->errors[INWT_FORWARDING_ERROR_PROTOCOL];
				continue;
			}

			if(PREDICT_TRUE(ip2->protocol == IP_PROTOCOL_IP4_INWT))
			{
				sr2 = (ip4_inwt_ip4option_sr_header_t *) (ip2 + 1);
				sr_header_processing(node, b2, ip2, sr2, &next2);
				// vlib_log_warn(iim->log_class, "inwt sr forwading dst ip: %U",
				// 	format_ip4_address, &ip2->dst_address);
			}
			else
			{
				b2->error = node->errors[INWT_FORWARDING_ERROR_PROTOCOL];
				continue;
			}

			if(PREDICT_TRUE(ip3->protocol == IP_PROTOCOL_IP4_INWT))
			{
				sr3 = (ip4_inwt_ip4option_sr_header_t *) (ip3 + 1);
				sr_header_processing(node, b3, ip3, sr3, &next3);
				// vlib_log_warn(iim->log_class, "inwt sr forwading dst ip: %U",
				// 	format_ip4_address, &ip3->dst_address);
			}
			else
			{
				b3->error = node->errors[INWT_FORWARDING_ERROR_PROTOCOL];
				continue;
			}

			vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
		}

		while(n_left_from > 0 && n_left_to_next > 0)
		{
			u32 bi0;
			vlib_buffer_t *b0;
			ip4_header_t *ip0 = 0;
			ip4_inwt_ip4option_sr_header_t *sr0 = 0;
			u32 next0 = INWT_FORWARDING_NEXT_IP4_LOOKUP;

			bi0 = from[0];
			to_next[0] = bi0;
			from += 1;
			to_next += 1;
			n_left_from -= 1;
			n_left_to_next -= 1;

			b0 = vlib_get_buffer(vm, bi0);
			ip0 = vlib_buffer_get_current(b0);
			if(PREDICT_TRUE(ip0->protocol == IP_PROTOCOL_IP4_INWT))
			{
				sr0 = (ip4_inwt_ip4option_sr_header_t *) (ip0 + 1);
				sr_header_processing(node, b0, ip0, sr0, &next0);
				// vlib_log_warn(iim->log_class, "inwt sr forwading dst ip: %U",
				// 	format_ip4_address, &ip0->dst_address);
			}
			else
			{
				b0->error = node->errors[INWT_FORWARDING_ERROR_PROTOCOL];
				continue;
			}
			vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
		}

		vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

	return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (inwt_sr_forwarding_node) = {
  .function = inwt_sr_forwarding,
  .name = "inwt-sr-forwarding",
  .vector_size = sizeof (u32),
  // .format_trace = format_inwt_sr_forwarding_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = INWT_FORWARDING_N_ERROR,
  .error_strings = inwt_forwarding_error_strings,
  .n_next_nodes = INWT_FORWARDING_N_NEXT,
  .next_nodes = {
#define _(s,n) [INWT_FORWARDING_NEXT_##s] = n,
    foreach_inwt_forwarding_next
#undef _
  },
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
