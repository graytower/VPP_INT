#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt.h>
#include <vnet/sample-inwt/inwt_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>

#include <vppinfra/vec_bootstrap.h>
#include <vppinfra/error.h>

#include <vlib/log.h>

/* Graph arcs */
#define foreach_inwt_probe_packet_next     \
_(ETHERNET_INPUT, "ethernet-input")         \
_(DROP, "error-drop")

typedef enum
{
#define _(s,n) INWT_PROBE_PACKET_NEXT_##s,
  foreach_inwt_probe_packet_next
#undef _
    INWT_PROBE_PACKET_N_NEXT,
} inwt_probe_packet_next_t;

/* INWT rewrite errors */
#define foreach_inwt_probe_packet_error                     \
_(NO_BUFFERS, "INWT no buffers error")

typedef enum
{
#define _(sym,str) INWT_PROBE_PACKET_ERROR_##sym,
  foreach_inwt_probe_packet_error
#undef _
    INWT_PROBE_PACKET_N_ERROR,
} inwt_probe_packet_error_t;

static char *inwt_probe_packet_error_strings[] = {
#define _(sym,string) string,
  foreach_inwt_probe_packet_error
#undef _
};

/*********************** SR rewrite string computation ************************/
/**
 * @brief SR rewrite string computation for SR header insertion
 */
static inline u8 *
compute_rewrite_sr(ip4_address_t * segments)
{
	u8 *result = NULL;
	ip4_inwt_ip4option_sr_header_t *inwt_srh;
	u8 header_length = 0;

	ip4_address_t *addrp, *this_address;

	header_length += sizeof(ip4_inwt_ip4option_sr_header_t);
	header_length += vec_len(segments) * sizeof(ip4_address_t);

	vec_validate(result, header_length-1);

	inwt_srh = (ip4_inwt_ip4option_sr_header_t *) result;
	inwt_srh->nop = 1;    //NOP 00000001
	inwt_srh->code = 137; //strict source routing
	inwt_srh->length = header_length;
	inwt_srh->pointer = 4;
	addrp = inwt_srh->dip_array;
	vec_foreach(this_address, segments)
	{
		clib_memcpy_fast(addrp->data, this_address->data, sizeof(ip4_address_t));
		addrp++;
	}
	return result;
}

/**
 * @brief INT rewrite string computation for INT header insertion
 */
static inline u8 *
compute_rewrite_int(u8 max_hop, u16 ins_map)
{
	u8 *result = NULL;
	ip4_inwt_int_header_t *inwt_inth;
	u8 header_length = 0;

	u8 *p_metadata_stack;

	header_length += sizeof(ip4_inwt_int_header_t);  //12 byte
	u8 length_metadata_stack = max_hop * 24;
	// u8 length_metadata_stack = find_length_via_ins_map(ins_map) * max_hop;
	header_length += length_metadata_stack;  //Currently, length of int_metadata per hop is 24 byte

	vec_validate(result, header_length-1);

	inwt_inth = (ip4_inwt_int_header_t *) result;
	inwt_inth->type = 1;   //hop-by-hop type
	inwt_inth->shim_header_reserved = 0;
	inwt_inth->length = header_length;
	inwt_inth->next_protocol = 0;
	inwt_inth->flags = 0x1000;
	inwt_inth->metadata_length_of_per_hop = 0x18;  //24 byte
	inwt_inth->pointer_to_hops = 0x0c;  // =12
	inwt_inth->instruction_bitmap = ins_map;
	inwt_inth->metadata_header_reserved = 0;
	p_metadata_stack = inwt_inth->metadata_stack;
	for(u8 i=0; i<length_metadata_stack; ++i)
		clib_memset(p_metadata_stack + i, 0, sizeof(*p_metadata_stack));
	return result;
}

/**
 * @brief Add SR header and INT header to an INWT policy
 */
static inline void
create_inwt_policy(ip4_inwt_policy_t * inwt_policy, ip4_address_t * segments, u8 max_hop, u16 ins_map)
{
	inwt_policy->rewrite_sr = compute_rewrite_sr(segments);
	inwt_policy->rewrite_int = compute_rewrite_int(max_hop, ins_map);
}

/******************************* INWT rewrite API *******************************/
/**
 * @brief Create a new INWT header
 *
 * @param segments is a vector of IPv4 address composing the source routing path
 * @param max_hop is the max hop number of INT path
 * @param ins_map is an instruction map of INT metadata
 *
 * @return 0 if correct, else error
 */
int
inwt_header_add(ip4_address_t * segments, u8 max_hop, u16 ins_map)
{
	ip4_inwt_main_t *iim = &ip4_inwt_main;
	ip4_inwt_policy_t *inwt_policy = 0;

	/* Add an INWT policy object */
	pool_get(iim->inwt_policies, inwt_policy);
	clib_memset(inwt_policy, 0, sizeof(*inwt_policy));
	create_inwt_policy(inwt_policy, segments, max_hop, ins_map);
	return 0;
}

/**
 * @brief CLI for 'inwt header' command family
 */
static clib_error_t *
inwt_header_rewrite_command_fn (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
	int rv = -1;
	int is_add = 0;
	u8 max_hop = (u8) ~ 0;
	u16 ins_map = (u16) ~ 0;
	ip4_address_t next_address;
	ip4_address_t *segments = 0, *this_seg;

	while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if(is_add==0 && unformat(input, "add"))
			is_add = 1;
		else if(unformat(input, "next %U", unformat_ip4_address, &next_address))
		{
			vec_add2(segments, this_seg, 1);
			clib_memcpy_fast(this_seg->data, next_address.data, sizeof(*this_seg));
		}
		else if(unformat(input, "maxhop %u", &max_hop));
		else if(unformat(input, "insmap 0x%x", &ins_map));
		else
			break;
	}

	if(is_add == 0)
		return clib_error_return(0, "Incorrect CLI");
	if(is_add == 1)
	{
		if(vec_len(segments) == 0)
			return clib_error_return(0, "No Source Routing Path specified");

		rv = inwt_header_add(segments, max_hop, ins_map);
		vec_free(segments);
	}

	switch(rv)
	{
		case 0:
			break;
		case 1:
			break;
		default:
			return clib_error_return(0, "BUG: inwt header rewrite returns %d", rv);
	}
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (inwt_header_rewrite_command, static) = {
	.path = "inwt header",
	.short_help = "inwt header add "
	  "next 10.0.1.0 next 10.0.2.0 next 10.0.3.0 "
	  "maxhop 3 insmap 0xffff",
	.function = inwt_header_rewrite_command_fn,
};
/* *INDENT-ON* */

/*************************** INWT rewrite graph node ****************************/

/**
 * @brief Get INWT probe template packet
 */
void *
inwt_packet_template_get_packet(vlib_main_t * vm,
				 vlib_packet_template_t * t, vlib_buffer_t *b0, u32 * bi_result)
{
  u32 bi;
  vlib_buffer_t *b;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;

  *bi_result = bi;

  b = vlib_get_buffer (vm, bi);
  if(vec_len (t->packet_data) != sizeof(ethernet_header_t)+sizeof(ip4_header_t))
  	return 0;
  clib_memcpy_fast (vlib_buffer_get_current (b),
		    vlib_buffer_get_current (b0), vec_len (t->packet_data));
  b->current_length = vec_len (t->packet_data);

  return b->data;
}

/**
 * @brief Graph node for applying an INWT policy into a packet.
 *        Generate INWT probe packet and insert INWT header.
 */
static uword
inwt_probe_packet_generation(vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
	ip4_inwt_main_t *iim = &ip4_inwt_main;
	u32 n_left_from, next_index, *from, *to_next;

	from = vlib_frame_vector_args (from_frame);
	n_left_from = from_frame->n_vectors;

	next_index = INWT_PROBE_PACKET_NEXT_DROP;

	// vlib_log_warn(iim->log_class, "enter into inwt probe packet generation node");

	while(n_left_from > 0)
	{
		u32 n_left_to_next;
		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

		while(n_left_from > 0 && n_left_to_next > 0)
		{
			u32 bi0;
			vlib_buffer_t *b0;

			u32 probe_numbers = 0;
			ip4_inwt_policy_t *inwt_policy = 0;
			ip4_inwt_policy_t **vec_policies = 0;

			bi0 = from[0];
			from += 1;
			n_left_from -= 1;
			to_next[0] = bi0;
			to_next += 1;
			n_left_to_next -= 1;

			b0 = vlib_get_buffer(vm, bi0);
			vlib_buffer_advance(b0, -(word)(sizeof(ethernet_header_t)+sizeof(ip4_header_t)+sizeof(udp_header_t)));

			pool_foreach(inwt_policy, iim->inwt_policies,
						{vec_add1(vec_policies, inwt_policy); } );

			int i = 0;
			vec_foreach_index(i, vec_policies)
			{
				ip4_inwt_template_header_t *h;
				vlib_buffer_t *c0;
				u32 ci0;

				inwt_policy = vec_policies[i];
				probe_numbers += 1;

				h = inwt_packet_template_get_packet(vm,
								&iim->inwt_probe_packet_template,
								b0,
								&ci0);
				if(PREDICT_FALSE(!h))
				{
					b0->error = node->errors[INWT_PROBE_PACKET_ERROR_NO_BUFFERS];
					continue;
				}

				// ethernet_header_t *log_l2 = &(h->l2_header);
				// vlib_log_warn(iim->log_class, "ip4_inwt_gen_template src_mac addr: %U",
				// 			format_mac_address, log_l2->src_address);
				
				c0 = vlib_get_buffer(vm, ci0);
				vnet_buffer(c0)->sw_if_index[VLIB_RX] = vnet_buffer(b0)->sw_if_index[VLIB_RX];

				ASSERT (c0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
					vec_len (inwt_policy->rewrite_sr) + vec_len (inwt_policy->rewrite_int));

				ip4_inwt_template_header_t *template_h0 = 0;
				template_h0 = vlib_buffer_get_current(c0);
				
				ip4_inwt_ip4option_sr_header_t *sr0 = 0;
				ip4_inwt_int_header_t *int0 = 0;
				/*
				insert IP4_option_SR and INT
				 */
				sr0 = (ip4_inwt_ip4option_sr_header_t *) (template_h0 + 1);
				int0 = (ip4_inwt_int_header_t *) (((void *) sr0) + vec_len(inwt_policy->rewrite_sr));

				clib_memcpy_fast((u8 *)template_h0 - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int),
					(u8 *)template_h0, sizeof(ethernet_header_t) + sizeof(ip4_header_t));
				clib_memcpy_fast((u8 *)sr0 - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int),
					inwt_policy->rewrite_sr, vec_len(inwt_policy->rewrite_sr));
				clib_memcpy_fast((u8 *)int0 - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int),
					inwt_policy->rewrite_int, vec_len(inwt_policy->rewrite_int));

				template_h0 = ((void *) template_h0) - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int);
				sr0 = ((void *) sr0) - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int);
				int0 = ((void *) int0) - vec_len(inwt_policy->rewrite_sr) - vec_len(inwt_policy->rewrite_int);

				/*
				rewrite ip4 header(length, protocol and checksum)
				modify sr and int headers
				advance pointer to mac_header
				copy trace flag
				 */
				u8 old_protocol = 0;
				u16 new_l0 = 0;
				ip4_header_t *ip0  = 0;
				u32 advance = 0;

				ip0 = &(template_h0->l3_header);
				new_l0 = vec_len(inwt_policy->rewrite_sr) + vec_len(inwt_policy->rewrite_int) + 0x14;

				// vlib_log_warn(iim->log_class, "ip4_inwt_gen_template sr length: %d",
				//  			vec_len(inwt_policy->rewrite_sr));
				// vlib_log_warn(iim->log_class, "ip4_inwt_gen_template int length: %d",
				//  			vec_len(inwt_policy->rewrite_int));

				ip0->length = clib_host_to_net_u16(new_l0);

				// vlib_log_warn(iim->log_class, "ip4_inwt_gen_template ip length: %d",
				//  			clib_net_to_host_u16 (ip0->length));

				old_protocol = ip0->protocol;
				ip0->protocol = IP_PROTOCOL_IP4_INWT;
				ip0->checksum = ip4_header_checksum(ip0);

				int0->next_protocol = old_protocol;

				advance = vec_len(inwt_policy->rewrite_int) + vec_len(inwt_policy->rewrite_sr);
				vlib_buffer_advance(c0, -(word)advance);

				vlib_buffer_copy_trace_flag(vm, b0, ci0);
				VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);

				vlib_set_next_frame_buffer (vm, node,
				      INWT_PROBE_PACKET_NEXT_ETHERNET_INPUT, ci0);
			}
		}

		vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

	return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (inwt_probe_packet_generation_node) = {
  .function = inwt_probe_packet_generation,
  .name = "inwt-probe-packet-generation",
  .vector_size = sizeof (u32),
  // .format_trace = format_inwt_probe_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = INWT_PROBE_PACKET_N_ERROR,
  .error_strings = inwt_probe_packet_error_strings,
  .n_next_nodes = INWT_PROBE_PACKET_N_NEXT,
  .next_nodes = {
#define _(s,n) [INWT_PROBE_PACKET_NEXT_##s] = n,
    foreach_inwt_probe_packet_next
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
