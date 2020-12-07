/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __VOM_GBP_BRIDGE_DOMAIN_CMDS_H__
#define __VOM_GBP_BRIDGE_DOMAIN_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/gbp_bridge_domain.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/gbp.api.vapi.hpp>

namespace VOM {
namespace gbp_bridge_domain_cmds {
/**
 * A command class that creates an Bridge-Domain
 */
class create_cmd
  : public rpc_cmd<HW::item<uint32_t>, vapi::Gbp_bridge_domain_add>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<uint32_t>& item,
             const handle_t bvi,
             const handle_t uu_fwd);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const create_cmd& i) const;

private:
  const handle_t m_bvi;
  const handle_t m_uu_fwd;
};

/**
 * A cmd class that Delete an Bridge-Domain
 */
class delete_cmd
  : public rpc_cmd<HW::item<uint32_t>, vapi::Gbp_bridge_domain_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<uint32_t>& item);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const delete_cmd& i) const;
};

/**
 * A cmd class that Dumps all the bridge domains
 */
class dump_cmd : public VOM::dump_cmd<vapi::Gbp_bridge_domain_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd() = default;
  dump_cmd(const dump_cmd& d) = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const dump_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

}; // gbp_bridge_domain_cmds
}; // VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
