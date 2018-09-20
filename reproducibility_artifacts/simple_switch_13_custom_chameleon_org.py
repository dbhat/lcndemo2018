# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import vlan

HARD_TIMEOUT = 0
IDLE_TIMEOUT = 300


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    buffer_id=buffer_id,
                                    priority=priority, 
                                    match=match,
                                    idle_timeout=IDLE_TIMEOUT, 
                                    #hard_timeout=HARD_TIMEOUT,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, 
                                    instructions=inst)

        datapath.send_msg(mod)

    def delete_flow(self, datapath, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port)

        mod = parser.OFPFlowMod(datapath=datapath, 
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, 
                                out_group=ofproto.OFPG_ANY,
                                priority=1, 
                                match=match)

        datapath.send_msg(mod)

        actions = [parser.OFPActionOutput(port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, 
                                command=ofproto.OFPFC_DELETE,
                                out_port=port, 
                                out_group=ofproto.OFPG_ANY,
                                instructions=inst)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
	vl = pkt.get_protocols(vlan.vlan)
        svl = pkt.get_protocols(vlan.svlan)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
		# learn a mac address to avoid FLOOD next time.
        if str(dpid)=="222594050208580":
		self.logger.info("Corsa2")
		return
	if in_port==1033:
		self.mac_to_port[dpid][src] = 2033
	else:
		self.mac_to_port[dpid][src] = in_port
	vlan_i=0
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
	    actions=[parser.OFPActionOutput(out_port)]
	else:
            actions = []
            out_port = ofproto.OFPP_ALL
	    if in_port==4533:
			list_out_hosts = [4514, 4519, 4526]
            		for p in list_out_hosts:
                		if in_port!=p:
                			actions.append(parser.OFPActionOutput(p))
	    		self.logger.info("ACTIONSCTRL%s"%actions)
	    elif in_port==1033 or in_port==2033:
		list_out_hosts = [4514,4519,4526]
            	for p in list_out_hosts:
                	if in_port!=p:
                		actions.append(parser.OFPActionOutput(p))
	    else:
		actions.append(parser.OFPActionOutput(out_port))
		#list_out_hosts = [4514,4517,4526,1033,4533,4537]
                #for p in list_out_hosts:
                #        if in_port!=p:
                #                actions.append(parser.OFPActionOutput(p))
		self.logger.info("ACTIONSHOST%s"%actions)
	self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
	if len(svl)>0:
                	self.logger.info("802.1AD: packet in %s %s %s %s DL_TYPE %s \nSVLAN info %s %s", dpid, src, dst, in_port, msg.match, svl, len(svl))
        if len(vl)>0:
                self.logger.info("802.1Q: packet in %s %s %s %s DL_TYPE %s \nVLAN info %s %s", dpid, src, dst, in_port, msg.match, vl, len(vl))
		#actions = [parser.OFPActionOutput(out_port)]
		actions = []
		self.logger.info("ACTIONS %s"%actions)
		header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols
                           if type(p) != str)
        	if header_list:
                #self.logger.info("HEADER_LIST:\n%s\n", header_list)
                	if 'vlan' in header_list:
                          if len(vl)>0:
                                self.logger.info('vid=%s', vl[0].vid+4096)
                                #vlan_i=(header_list['vlan'].vid+4096)
                                vlan_i=vl[0].vid+4096
                          if vlan_i==4199:
                                if in_port==4514:
                                        out_port=4526
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4299))
					#actions.append(parser.OFPActionPushVlan(33024))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=506))
                                elif in_port==4526:
                                        out_port=4514
					#actions.append(parser.OFPActionSetField(vlan_vid=4199))
                                        #vlan_i=(vl[0].vid+4096)
                                        #actions.append(parser.OFPActionSetField(vlan_vid=(svl[0].vid+4096)))
                                        #actions.append(parser.OFPActionPushVlan(33024))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4197))
                                        #actions.append(parser.OFPActionPopVlan())
                                        #actions.append(parser.OFPActionPushVlan(33024))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=svl[0].vid))
                          elif vlan_i==4298:
                                if in_port==1033:
                                        out_port=4526
                                        #actions.append(parser.OFPActionPushVlan(34984))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4298))
                                elif in_port==4526:
                                        out_port=2033
					#actions.append(parser.OFPActionSetField(vlan_vid=4298))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4198))
            		  elif vlan_i==4299:
                                if in_port==1033:
                                        out_port=4526
                                        #actions.append(parser.OFPActionPushVlan(34984))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=508))
                                elif in_port==4526:
                                        out_port=1033
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4297))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4198))
                          elif vlan_i==4300:
                                if in_port==2033:
                                        out_port=4526
                                        #actions.append(parser.OFPActionPushVlan(34984))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=508))
                                elif in_port==4526:
                                        out_port=2033
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4297))
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4198))
	                  elif vlan_i==4598:
                                if in_port==4519:
                                        out_port=1033
                                        #actions.append(parser.OFPActionSetField(vlan_vid=4597))
                                elif in_port==1033:
                                        out_port=4519 
			  actions.append(parser.OFPActionOutput(out_port))
                          self.logger.info("OUT_PORT %s",out_port)
                	else:
                        	vlan_i=0
        # install a flow to avoid packet_in next time
	if out_port != ofproto.OFPP_ALL:
            priority = 1
            if vlan_i==0:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, vlan_vid=vlan_i)
            else:
                match = parser.OFPMatch(in_port=in_port, vlan_vid=vlan_i)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                        return
            else:
                self.add_flow(datapath, priority, match, actions)
	    '''
	    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                priority = 1
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                return
            else:
                priority = 1
                self.add_flow(datapath, priority, match, actions)
            '''
	data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dp = msg.datapath

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
            self.delete_flow(dp,port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
