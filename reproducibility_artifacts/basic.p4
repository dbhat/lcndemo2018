/* -*- P4_16 -*- */
/*This code is targeted at processing HTTP/2 Stream ID headers in the P4 pipeline to perform application-header based TE. TCP Options Parser Adapted From: https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4*/
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_VLANAD = 0x88A8;
const bit<48> SRC_ADDR = 0x246e967e12ba;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<16>  HTTP_PORT_NO = 16w80;
const bit<16> IPERF_PORT_NO=16w5001;
const bit<16> SSH_PORT_NO=16w22;
const bit<32> SRC_HOST = 0x0a0a0a04;
const bit<32> STREAM_ID_THRESH=32w1;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<12> vlanID_t;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header vlan_tag_t {
    bit<3>    pcp;  
    bit<1>    cfi;
    bit<12>   vid;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    macAddr_t  sha;
    ip4Addr_t spa;
    macAddr_t  tha;
    ip4Addr_t tpa;
}


header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<4>  ctrl1;
    bit<1>  syn;
    bit<1>  ctrl2;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_option_t{
    varbit<512> tcp_opt_h;
}

/*To get header length: Take the value of dataOffset, multiply it by 32 and divide the result by 8: 7x32=224/8=28 bytes*/

header http2_t {
    bit<24> h_len;
    bit<8>  h_type;
    bit<8>  h_flags;
    bit<32> h_sid;
	
}
header queueing_metadata_t {
    bit<48> enq_timestamp;
    bit<24> enq_qdepth;
    bit<32> deq_timedelta;
    bit<24> deq_qdepth;
    bit<8>  qid;
}


struct metadata {
    /* empty */
    queueing_metadata_t queueing_metadata;
}
struct headers {
    ethernet_t    ethernet;
    vlan_tag_t    vlan_tag;
    //vlan_tag_t[2] vlan_tag_double;
    arp_t         arp;
    arp_ipv4_t    arp_ipv4;
    ipv4_t        ipv4;
    icmp_t        icmp;
    tcp_t	  tcp;
    tcp_option_t  tcp_options;
    http2_t       http2;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TCP_option_parser(packet_in b, in bit<16> ip_hdr_len,  in bit<4> tcp_hdr_data_offset, out tcp_option_t tcp_option)
{
  bit<7> tcp_hdr_bytes_left;
  state start {
  	verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
  	tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        //tcp_hdr_bytes_left = ((4* (bit<7>)(tcp_hdr_data_offset)-20));
  	transition consume_remaining_tcp_hdr_and_accept;
  }
  state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(tcp_option, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }

}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            //TYPE_VLANAD	   : parse_vlan_tag;
	    ETHERTYPE_VLAN : parse_vlan_tag_single;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default        : accept;
        }
    }
    state parse_vlan_tag_single {
        packet.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.etherType) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    /*state parse_vlan_tag {
        packet.extract(hdr.vlan_tag_double.next);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN : parse_vlan_tag;
	    ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }*/
    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	    IPPROTO_ICMP  : parse_icmp;
            IPPROTO_TCP   : parse_tcp;
	    default      : accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition select(hdr.ipv4.dstAddr) {
		SRC_HOST: accept;
		default: accept;
	}
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
	TCP_option_parser.apply(packet, hdr.ipv4.totalLen, hdr.tcp.dataOffset, hdr.tcp_options);
        transition select(hdr.tcp.dstPort) {
	HTTP_PORT_NO: parse_http2;
	1 : accept;
	IPERF_PORT_NO: accept;
        default: parse_tcp_syn;
	}
	//transition accept;
    }
    state parse_tcp_syn{
         transition select(hdr.tcp.srcPort){
		HTTP_PORT_NO: parse_http2;
		IPERF_PORT_NO: accept;
		default : accept;	
	}
    }
 
    state parse_http2 {
    	packet.extract(hdr.http2);
        transition select(hdr.http2.h_sid){
	 	1: accept;
		3: accept;  	
		default: accept;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    counter(1, CounterType.packets_and_bytes) vlan_ip_stats;
    action drop_with_count() {
        mark_to_drop();
    }
 
    /*action push_double_vtag(vlanID_t vlan_id1, vlanID_t vlan_id2,egressSpec_t port, macAddr_t srcaddr) {
        standard_metadata.egress_spec = port;
	hdr.vlan_tag_double[0].setValid();
	hdr.vlan_tag_double[1].setValid();
	hdr.vlan_tag_double[0].vid=vlan_id1;
        hdr.vlan_tag_double[0].etherType=hdr.ethernet.etherType;
	//hdr.vlan_tag_double[1]=hdr.vlan_tag;
	hdr.vlan_tag_double[1].vid=vlan_id2;
	hdr.vlan_tag_double[1].etherType=ETHERTYPE_VLAN;
	hdr.vlan_tag.setInvalid();
	hdr.ethernet.etherType=TYPE_VLANAD;
	hdr.ethernet.srcAddr=srcaddr;
    }*/
    action push_vtag(vlanID_t vlan_id, egressSpec_t port, macAddr_t srcaddr){
   	standard_metadata.egress_spec = port;
	hdr.vlan_tag.vid=vlan_id;
	hdr.ethernet.srcAddr=srcaddr; 
   }
   action push_vtag_ip(vlanID_t vlan_id, egressSpec_t port, macAddr_t srcaddr){
        standard_metadata.egress_spec = port;
        hdr.vlan_tag.vid=vlan_id;
        hdr.ethernet.srcAddr=srcaddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        vlan_ip_stats.count((bit<32>) hdr.vlan_tag.vid);
   
    }
   /*table vlan_ip {
        key = {
		standard_metadata.ingress_port: exact;
		hdr.vlan_tag.vid: exact;
		hdr.vlan_tag.etherType: exact;
		//hdr.ethernet.srcAddr: exact;
	}
	actions = {
		drop_with_count;
		forward;
    	}
        size = 1024;
        default_action = drop_with_count;
    }*/
    apply {
	    //queueing_metadata_t queueing_metadata;
	    //queueing_metadata.enq_qdepth=1000;
	    //queueing_metadata.deq_qdepth=;
	    //if (standard_metadata.ingress_port==3){
		if ((hdr.tcp.dstPort==SSH_PORT_NO) || (hdr.tcp.srcPort==SSH_PORT_NO)){
			drop_with_count();
		}
		if (hdr.http2.isValid()){
                        if (hdr.tcp.srcPort==HTTP_PORT_NO){
                                if (hdr.http2.h_sid>STREAM_ID_THRESH){
					standard_metadata.egress_spec = 3;
                                        //push_vtag_ip(203,3,SRC_ADDR);
                                }
                                else if (hdr.http2.h_sid<=STREAM_ID_THRESH){
                                        standard_metadata.egress_spec = 4;
					//push_vtag_ip(204,3,SRC_ADDR);
                                }
				else{
					standard_metadata.egress_spec = 4;
					//push_vtag_ip(203,3,SRC_ADDR);
				}
                        }
                        else if (hdr.tcp.dstPort==HTTP_PORT_NO){
                                standard_metadata.egress_spec = 1;
				//push_vtag_ip(103,3,SRC_ADDR);
                        }
                }
		else if(hdr.ethernet.isValid()){
			if (standard_metadata.ingress_port==1){
                                standard_metadata.egress_spec = 4;
                        }
                        else if (standard_metadata.ingress_port==4) {
                                standard_metadata.egress_spec = 1;
                        }
			/*if (hdr.ipv4.srcAddr==SRC_HOST){
                                push_vtag(103, 3, SRC_ADDR);
                        }
                        else if (hdr.ipv4.dstAddr==SRC_HOST){
                                push_vtag(203, 3, SRC_ADDR);
                        }*/
                }
		/*
		else if(hdr.tcp.isValid()){
			if ((hdr.tcp.srcPort==HTTP_PORT_NO) || (hdr.tcp.srcPort==IPERF_PORT_NO)){
                                push_vtag_ip(103, 3, SRC_ADDR);
                        }
                        else if ((hdr.tcp.dstPort==HTTP_PORT_NO)|| (hdr.tcp.dstPort==IPERF_PORT_NO)){
                                push_vtag_ip(202, 3, SRC_ADDR);
                        } 
		}
		else if (hdr.vlan_tag.isValid()){
                                if (hdr.vlan_tag.vid==103){
					push_vtag(202,3, SRC_ADDR);
                		}
                		else if (hdr.vlan_tag.vid==202){
                                	push_vtag(103,3, SRC_ADDR);
				}			
 	    	}*/
	    	else {
			drop_with_count();
		}
			
	    }
	    //vlan_ip.apply();
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { 
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        /*update_checksum_with_payload(
	    hdr.tcp.isValid(),
	    {  	hdr.tcp.srcPort,
    	       	hdr.tcp.dstPort,
    		hdr.tcp.seqNo,
    		hdr.tcp.ackNo,
    		hdr.tcp.dataOffset,
    		hdr.tcp.res,
    		hdr.tcp.ecn,
    		hdr.tcp.ctrl1,
	 	hdr.tcp.syn,
		hdr.tcp.ctrl2,
    		hdr.tcp.window,
    		hdr.tcp.urgentPtr}, hdr.tcp.checksum, HashAlgorithm.csum16);
   */
   }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
 	packet.emit(hdr.ethernet);
        //packet.emit(hdr.vlan_tag);
        //packet.emit(hdr.vlan_tag_double);
	/* ARP Case */
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        /* IPv4 case */
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
	packet.emit(hdr.tcp);
	packet.emit(hdr.tcp_options);
	packet.emit(hdr.http2);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
