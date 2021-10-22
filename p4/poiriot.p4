#include <core.p4>
#include <tna.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x800;
const bit<3> RESUB = 3w1;

//Parameters
#define TIMESTAMP ig_prsr_md.global_tstamp[47:16]
#define TIMEOUT 91552
#define CONNECTIONS 65535
#define DEVICES 256
#define DEV_WIDTH 8

#define REPORT_SERVER_SW_PORT 140

#include "headers.p4"
#include "state_machine.p4"
#include "egress.p4"

parser TofinoIngressParser(
        packet_in pkt,
        inout ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        pkt.extract(ig_md.resub_hdr);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
	ig_md.resub_hdr = {0, 0, 0};
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Resubmit() resubmit;

    apply {

        if (ig_dprsr_md.resubmit_type == RESUB) {
            resubmit.emit<resub_t>(ig_md.resub_hdr);
        }
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Main Logic Blocks
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {


    State_Machine() fsm1;

    action drop() {
        ig_dprsr_md.drop_ctl = 0;
    }

    //Count how many packets pass through the length filter
    Counter<bit<32>, bit<1>>(2, CounterType_t.PACKETS) p_stat;

    table length_filter {
        key = {
            hdr.ipv4.totalLen: exact;
        }
        actions = {
          NoAction;
        }
        size = 2048;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.tcp.isValid()) { //All devices are TCP for now

                // if it passes through the filter, check state machine
                if (length_filter.apply().hit) {
    	    	    p_stat.count(0);
                    fsm1.apply(hdr, ig_md, ig_intr_md, ig_prsr_md, ig_dprsr_md);
                }
                else {
                    p_stat.count(1);
                }
            }
        }

        //Forward detected device packets to server
        if (ig_md.resub_hdr.device_id != 0) {
            ig_tm_md.ucast_egress_port = REPORT_SERVER_SW_PORT;
        }
        else {
            drop();
        }
        ig_tm_md.bypass_egress = 1w1;
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
