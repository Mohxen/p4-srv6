/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /*
 * Edited by Mohsen Rahmati
 */

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** D E F I N E  *************************************
*************************************************************************/

// port_num_t: A 9-bit field representing port numbers (ingress/egress ports).
// group_id_t: A 16-bit field used for multicast or group IDs.
// l4_port_t: A 16-bit field representing Layer 4 port numbers (e.g., TCP or UDP ports).
typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ARP  = 0x0806;

// PROTO_ICMPV6: 58, indicating ICMPv6 for IPv6.
// PROTO_IP_IN_IP: 4, indicating IP-in-IP tunneling (an IP packet encapsulated inside another IP packet).
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_SRV6 = 43;
const bit<8> PROTO_ICMPV6 = 58;
const bit<8> PROTO_IPV6 = 41;
const bit<8> PROTO_IP_IN_IP = 4;

// ICMP6_TYPE_NS: 135, representing an ICMPv6 Neighbor Solicitation (NS) message.
// ICMP6_TYPE_NA: 136, representing an ICMPv6 Neighbor Advertisement (NA) message.
const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;

// NDP_OPT_TARGET_LL_ADDR: Option type 2, indicating the target link-layer address in NDP.
// IPV6_MCAST_01: A multicast MAC address (33:33:00:00:00:01), used for IPv6 multicast.
// NDP_FLAG_ROUTER: 0x80000000, indicates the presence of a router in NDP messages.
// NDP_FLAG_SOLICITED: 0x40000000, marks a solicited NDP response.
// NDP_FLAG_OVERRIDE: 0x20000000, allows overriding cached entries in NDP.
const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;
const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;
const bit<32> NDP_FLAG_ROUTER = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE = 0x20000000;

//transition from clone3()
// BMV2_V1MODEL_INSTANCE_TYPE_NORMAL: Regular packet processing.
// BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE: Packet is cloned at the ingress stage.
// BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE: Packet is cloned at the egress stage.
// BMV2_V1MODEL_INSTANCE_TYPE_COALESCED: Coalesced packet processing.
// BMV2_V1MODEL_INSTANCE_TYPE_RECIRC: Packet is recirculated for additional processing.
// BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION: Packet is replicated for multicast or similar purposes.
// BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT: Packet is resubmitted to the pipeline for re-processing.
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// This defines the maximum number of segments (or hops) in the SRv6 header list, used later in the srv6_list_t.
#define MAX_HOPS 4

// These define the headers for the controller to switch communication, specifically for ingress and egress packet information.
// ingress_port and egress_port are fields representing the incoming and outgoing port numbers, respectively.
// _pad is a padding field to align the structure in memory.
@controller_header("packet_in")
header packet_in_header_t {
    port_num_t ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out")
header packet_out_header_t {
    port_num_t egress_port;
    bit<7> _pad;
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

// Represents the Segment Routing Header (SRH) for SRv6:
// next_hdr: Type of the next header.
// segment_left: Indicates how many segments are left in the list.
// last_entry: The index of the last entry in the SRH.
// Other fields are used for routing type, flags, and optional tags.
header srv6h_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> segment_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}


// Defines an SRv6 segment list entry, where segment_id is a 128-bit IPv6 address representing a segment. 
// The list holds multiple segments, allowing packets to traverse a series of waypoints.
header srv6_list_t {
    bit<128> segment_id;
}

// Defines the ARP header for resolving IP addresses to MAC addresses:
// hw_type: Hardware type (e.g., Ethernet).
// proto_type: Protocol type (e.g., IPv4).
// opcode: Indicates ARP request or reply.
header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

// Defines the ICMPv6 header, similar to ICMP but used in IPv6 networks.
header icmpv6_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

// Defines the NDP headers for IPv6 address resolution and router advertisement:
// ndp_t: Includes flags and a target address.
// ndp_option_t: Holds options related to NDP.
header ndp_t {
    bit<32> flags;
    bit<128> target_addr;
}

header ndp_option_t {
    bit<8> type;
    bit<8> length;
    bit<48> value;
}

const bit<8> CLONE_FL_clone3  = 3; 
struct preserving_metadata_CPU_t {
    @field_list(CLONE_FL_clone3)
    bit<9> ingress_port;
    @field_list(CLONE_FL_clone3)
    bit<9> egress_port;
}

// Defines custom metadata used in the pipeline:
// is_multicast: Flag to indicate if the packet is multicast.
// skip_l2: A flag to skip Layer 2 processing.
// xconnect: Cross-connection flag.
// next_srv6_sid: Stores the next SRv6 segment.
// ua_next_hop: Stores the next hop for SRv6 uSID.
struct local_metadata_t {                   
    bool is_multicast;
    bool skip_l2;
    bool xconnect;
    ipv6_addr_t next_srv6_sid;
    ipv6_addr_t ua_next_hop;
    bit<8> ip_proto;
    bit<8> icmp_type;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bool ipv4_update;
    preserving_metadata_CPU_t perserv_CPU_meta; //to migrate from clone3() to clone_preserving() in the clone_to_CPU scenario
}

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv6_t ipv6;
    ipv6_t ipv6_inner;
    ipv4_t ipv4;
    srv6h_t srv6h;
    srv6_list_t[MAX_HOPS] srv6_list;
    arp_t arp;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
    ndp_option_t ndp_option;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRV6: parse_srv6;
            PROTO_IPV6: parse_ipv6_inner;
            PROTO_IP_IN_IP: parse_ipv4;
            default: accept;
        }
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }
    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            _: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        // current metadata
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }
    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_IPV6: parse_ipv6_inner;
            PROTO_IP_IN_IP: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        //Need header verification?
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6_inner {
        packet.extract(hdr.ipv6_inner);

        transition select(hdr.ipv6_inner.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }

    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition parse_ndp_option;
    }

    state parse_ndp_option {
        packet.extract(hdr.ndp_option);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta) {
    apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

#define CPU_CLONE_SESSION_ID 99
#define UN_BLOCK_MASK     0xffffffff000000000000000000000000

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }
    action set_multicast_group(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    direct_counter(CounterType.packets_and_bytes) unicast_counter; 
    table unicast {
        key = {
            hdr.ethernet.dst_addr: exact; 
        }
        actions = {
            set_output_port;
            drop;
            NoAction;
        }
        counters = unicast_counter;
        default_action = NoAction();
    }

    direct_counter(CounterType.packets_and_bytes) multicast_counter;
    table multicast {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            drop;
        }
        counters = multicast_counter;
        const default_action = drop;
    }

    direct_counter(CounterType.packets_and_bytes) l2_firewall_counter;
    table l2_firewall {
	    key = {
	        hdr.ethernet.dst_addr: exact;
	    }
	    actions = {
	        NoAction;
	    }
    	counters = l2_firewall_counter;
    }

    action set_next_hop(mac_addr_t next_hop) {
	    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
	    hdr.ethernet.dst_addr = next_hop;
	    hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    // TODO: implement ecmp with ipv6.src+ipv6.dst+ipv6.flow_label
    // action_selector(HashAlgorithm.crc16, 32w64, 32w10) ip6_ecmp_selector;
    direct_counter(CounterType.packets_and_bytes) routing_v6_counter;
    table routing_v6 {
	    key = {
	        hdr.ipv6.dst_addr: lpm;

            hdr.ipv6.flow_label : selector;
            hdr.ipv6.dst_addr : selector;
            hdr.ipv6.src_addr : selector;
	    }
        actions = {
	        set_next_hop;
        }
        counters = routing_v6_counter;
        //implementation = ip6_ecmp_selector;
    }

    // TODO calc checksum
    action set_next_hop_v4(mac_addr_t next_hop) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = next_hop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        local_metadata.ipv4_update = true;
    }

    direct_counter(CounterType.packets_and_bytes) routing_v4_counter;
    table routing_v4 {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            set_next_hop_v4;
        }
        counters = routing_v4_counter;
    }

    /*
     * NDP reply table and actions.
     * Handles NDP router solicitation message and send router advertisement to the sender.
     */
    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        bit<128> host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp_option.setValid();
        hdr.ndp_option.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp_option.length = 1;
        hdr.ndp_option.value = target_mac;
        hdr.ipv6.next_hdr = PROTO_ICMPV6;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        local_metadata.skip_l2 = true;
    }

    direct_counter(CounterType.packets_and_bytes) ndp_reply_table_counter;
    table ndp_reply_table {
        key = {
            hdr.ndp.target_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        counters = ndp_reply_table_counter;
    }

    action srv6_end() {}

    action srv6_usid_un() {
        hdr.ipv6.dst_addr = (hdr.ipv6.dst_addr & UN_BLOCK_MASK) | ((hdr.ipv6.dst_addr << 16) & ~((bit<128>)UN_BLOCK_MASK));
    }

    action srv6_usid_ua(ipv6_addr_t next_hop) {
        hdr.ipv6.dst_addr = (hdr.ipv6.dst_addr & UN_BLOCK_MASK) | ((hdr.ipv6.dst_addr << 32) & ~((bit<128>)UN_BLOCK_MASK));
        local_metadata.xconnect = true;

        local_metadata.ua_next_hop = next_hop;
    }

    action srv6_end_x(ipv6_addr_t next_hop) {
        hdr.ipv6.dst_addr = (hdr.ipv6.dst_addr & UN_BLOCK_MASK) | ((hdr.ipv6.dst_addr << 32) & ~((bit<128>)UN_BLOCK_MASK));
        local_metadata.xconnect = true;

        local_metadata.ua_next_hop = next_hop;
    }

    action srv6_end_dx6() {
        hdr.ipv6.version = hdr.ipv6_inner.version;
        hdr.ipv6.traffic_class = hdr.ipv6_inner.traffic_class;
        hdr.ipv6.flow_label = hdr.ipv6_inner.flow_label;
        hdr.ipv6.payload_len = hdr.ipv6_inner.payload_len;
        hdr.ipv6.next_hdr = hdr.ipv6_inner.next_hdr;
        hdr.ipv6.hop_limit = hdr.ipv6_inner.hop_limit;
        hdr.ipv6.src_addr = hdr.ipv6_inner.src_addr;
        hdr.ipv6.dst_addr = hdr.ipv6_inner.dst_addr;

        hdr.ipv6_inner.setInvalid();
        hdr.srv6h.setInvalid();
        hdr.srv6_list[0].setInvalid();
    }

    action srv6_end_dx4()  {
        hdr.srv6_list[0].setInvalid();
        hdr.srv6h.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.ipv6_inner.setInvalid();

        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    } 

    direct_counter(CounterType.packets_and_bytes) srv6_localsid_table_counter;
    table srv6_localsid_table {
        key = {
            hdr.ipv6.dst_addr: lpm;
        }
        actions = {
            srv6_end;
            srv6_end_x;
            srv6_end_dx6;
            srv6_end_dx4;
            srv6_usid_un;
            srv6_usid_ua;
            NoAction;
        }
        default_action = NoAction;
        counters = srv6_localsid_table_counter;
    }

    action xconnect_act(mac_addr_t next_hop) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = next_hop;
    }

    direct_counter(CounterType.packets_and_bytes) xconnect_table_counter;
    table xconnect_table {
        key = {
            local_metadata.ua_next_hop: lpm;
        }
        actions = {
            xconnect_act;
            NoAction;
        }
        default_action = NoAction;
        counters = xconnect_table_counter;
    }

    action usid_encap_1(ipv6_addr_t src_addr, ipv6_addr_t s1) {
        hdr.ipv6_inner.setValid();

        hdr.ipv6_inner.version = 6;
        hdr.ipv6_inner.traffic_class = hdr.ipv6.traffic_class;
        hdr.ipv6_inner.flow_label = hdr.ipv6.flow_label;
        hdr.ipv6_inner.payload_len = hdr.ipv6.payload_len;
        hdr.ipv6_inner.next_hdr = hdr.ipv6.next_hdr;
        hdr.ipv6_inner.hop_limit = hdr.ipv6.hop_limit;
        hdr.ipv6_inner.src_addr = hdr.ipv6.src_addr;
        hdr.ipv6_inner.dst_addr = hdr.ipv6.dst_addr;

        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        hdr.ipv6.next_hdr = PROTO_IPV6;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.dst_addr = s1;
    }

    action usid_encap_2(ipv6_addr_t src_addr, ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6_inner.setValid();

        hdr.ipv6_inner.version = 6;
        hdr.ipv6_inner.traffic_class = hdr.ipv6.traffic_class;
        hdr.ipv6_inner.flow_label = hdr.ipv6.flow_label;
        hdr.ipv6_inner.payload_len = hdr.ipv6.payload_len;
        hdr.ipv6_inner.next_hdr = hdr.ipv6.next_hdr;
        hdr.ipv6_inner.hop_limit = hdr.ipv6.hop_limit;
        hdr.ipv6_inner.src_addr = hdr.ipv6.src_addr;
        hdr.ipv6_inner.dst_addr = hdr.ipv6.dst_addr;

        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40 + 24;
        hdr.ipv6.next_hdr = PROTO_SRV6;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.dst_addr = s1;

        hdr.srv6h.setValid();
        hdr.srv6h.next_hdr = PROTO_IPV6;
        hdr.srv6h.hdr_ext_len = 0x2;
        hdr.srv6h.routing_type = 0x4;
        hdr.srv6h.segment_left = 0;
        hdr.srv6h.last_entry = 0;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;

        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_encap_table_counter;
    table srv6_encap {
        key = {
           hdr.ipv6.dst_addr: lpm;       
        }
        actions = {
            usid_encap_1;
            usid_encap_2;
            NoAction;
        }
        default_action = NoAction;
        counters = srv6_encap_table_counter;
    }

    action usid_encap_1_v4(ipv6_addr_t src_addr, ipv6_addr_t s1) {
        hdr.ipv6.setValid();

        hdr.ipv6.version = 6;
        hdr.ipv6.traffic_class = hdr.ipv4.dscp ++ hdr.ipv4.ecn; 
        hash(hdr.ipv6.flow_label, 
                HashAlgorithm.crc32, 
                (bit<20>) 0, 
                { 
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    local_metadata.ip_proto,
                    local_metadata.l4_src_port,
                    local_metadata.l4_dst_port
                },
                (bit<20>) 1048575);
        hdr.ipv6.payload_len = hdr.ipv4.total_len;
        hdr.ipv6.next_hdr = PROTO_IP_IN_IP;
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.dst_addr = s1;

        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
    }

    action usid_encap_2_v4(ipv6_addr_t src_addr, ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6.setValid();

        hdr.ipv6.version = 6;
        hdr.ipv6.traffic_class = hdr.ipv4.dscp ++ hdr.ipv4.ecn; 
        hash(hdr.ipv6.flow_label, 
                HashAlgorithm.crc32, 
                (bit<20>) 0, 
                { 
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    local_metadata.ip_proto,
                    local_metadata.l4_src_port,
                    local_metadata.l4_dst_port
                },
                (bit<20>) 1048575);        
        hdr.ipv6.payload_len = hdr.ipv4.total_len + 24;
        hdr.ipv6.next_hdr = PROTO_SRV6;
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.dst_addr = s1;

        hdr.srv6h.setValid();
        hdr.srv6h.next_hdr = PROTO_IP_IN_IP;
        hdr.srv6h.hdr_ext_len = 0x2;
        hdr.srv6h.routing_type = 0x4;
        hdr.srv6h.segment_left = 0;
        hdr.srv6h.last_entry = 0;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;

        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;

        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
    }

    // create one group 
    action_selector(HashAlgorithm.crc16, 32w64, 32w10) ecmp_selector;
    direct_counter(CounterType.packets_and_bytes) srv6_encap_v4_table_counter;
    table srv6_encap_v4 {
        key = {
            hdr.ipv4.dscp: exact;
            hdr.ipv4.dst_addr: lpm;

            hdr.ipv4.src_addr: selector;
            hdr.ipv4.dst_addr: selector;
            local_metadata.ip_proto: selector;
            local_metadata.l4_src_port: selector;
            local_metadata.l4_dst_port: selector;
        }
        actions = {
            usid_encap_1_v4;
            usid_encap_2_v4;
            NoAction;
        }
        default_action = NoAction;
        implementation = ecmp_selector;
        counters = srv6_encap_v4_table_counter;
    }


    /*
     * ACL table  and actions.
     * Clone the packet to the CPU (PacketIn) or drop.
     */

    action clone_to_cpu() {
        //clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, standard_metadata); //DEPRACTED need OG project compiler
        local_metadata.perserv_CPU_meta.ingress_port = standard_metadata.ingress_port;
        local_metadata.perserv_CPU_meta.egress_port = CPU_PORT;                         //the packet only gets the egress right before egress, so we use CPU_PORT value
        clone_preserving_field_list(CloneType.I2E, CPU_CLONE_SESSION_ID, CLONE_FL_clone3);
    }

    direct_counter(CounterType.packets_and_bytes) acl_counter;
    table acl {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.ether_type: ternary;
            local_metadata.ip_proto: ternary;
            local_metadata.icmp_type: ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
        }
        actions = {
            clone_to_cpu;
            drop;
        }
        counters = acl_counter;
    }

    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }

        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_reply_table.apply();
        }

	    if (hdr.ipv6.hop_limit == 0) {
	        drop();
	    }

	    if (l2_firewall.apply().hit) {
            switch(srv6_localsid_table.apply().action_run) {
                srv6_end: {
                    // support for reduced SRH
                    if (hdr.srv6h.segment_left > 0) {
                        // set destination IP address to next segment
                        hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
                        // decrement segments left
                        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
                    } else {
                        // set destination IP address to next segment
                        hdr.ipv6.dst_addr = hdr.srv6_list[0].segment_id;
                    }
                }
                srv6_end_dx4: {
                    routing_v4.apply();
                }
            }

            // SRv6 Encapsulation
            if (hdr.ipv4.isValid() && !hdr.ipv6.isValid()) {
                srv6_encap_v4.apply();
            } else {
                srv6_encap.apply();
            }
            
            if (!local_metadata.xconnect) {
	            routing_v6.apply();
	        } else {
                xconnect_table.apply();
            }
        }
        
	    if (!local_metadata.skip_l2) {
            if (!unicast.apply().hit) {
       	      	multicast.apply();
	        }	
	    }
        
        acl.apply();
    
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE) {
            // write code here that works the same was as the original, except it uses
            // only metadata field values that you have explicitly preserved.
            if (local_metadata.perserv_CPU_meta.egress_port == CPU_PORT) { //packets for the controller, being a cloned packet we look at the struct
                hdr.packet_in.setValid();
                hdr.packet_in.ingress_port = local_metadata.perserv_CPU_meta.ingress_port;
            }
            if (local_metadata.is_multicast == true && local_metadata.perserv_CPU_meta.ingress_port == local_metadata.perserv_CPU_meta.egress_port) {
                mark_to_drop(standard_metadata);
            }
        } else if ((standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_NORMAL) || (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION))  {
            // Put a copy of the original egress code here, which seems to have been
            // written assuming that all standard_metadata fields were preserved, which
            // should be the case for NORMAL packets.
            if (standard_metadata.egress_port == CPU_PORT) {
                hdr.packet_in.setValid();
                hdr.packet_in.ingress_port = standard_metadata.ingress_port;		
            }
            if (local_metadata.is_multicast == true && standard_metadata.ingress_port == standard_metadata.egress_port) {
                mark_to_drop(standard_metadata);
            }
        } else {
            // Not clear to me whether you need any further branches to handle other
            // cases of the value of instance_type, but if. you want to be cautious
            // I would put a log_msg() extern call here that prints a special message
            // you can easily 'grep' for in the log files to see if this ever happens.
            log_msg("Unexpected instance_type in EgressPipeImpl: ", { standard_metadata.instance_type });
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t meta) {
    apply {
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_addr,
                hdr.ndp_option.type,
                hdr.ndp_option.length,
                hdr.ndp_option.value
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );

        update_checksum(meta.ipv4_update, 
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                16w0,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            }, 
            hdr.ipv4.hdr_checksum, 
            HashAlgorithm.csum16
        );

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.ipv6_inner);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
        packet.emit(hdr.ndp_option);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;