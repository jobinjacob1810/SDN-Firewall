from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import json

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def _init_(self, *args, **kwargs):
        super(SimpleFirewall, self)._init_(*args, **kwargs)
        self.mac_to_port = {}
        self.load_firewall_rules()

    def load_firewall_rules(self):
        self.rules = []
        try:
            with open('firewall_rules.json', 'r') as rule_file:
                self.rules = json.load(rule_file)
                self.logger.info("Loaded %d firewall rules.", len(self.rules))
        except Exception as e:
            self.logger.error("Error loading firewall rules: %s", e)
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
    	# self.logger.info("loaded switch features ")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info("loaded switch features ")

        # Install a default rule to allow all traffic.
        match = parser.OFPMatch()
        self.logger.info("parsed ofp match")
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
        self.logger.info("created actions")
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("added flow")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info("loaded packet_in_handler")

        pkt = packet.Packet(msg.data)
        self.logger.info("created packet")
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.info("fetched eth")

        try:
            if eth.ethertype == ethernet.ETH_TYPE_IP:
                ip = pkt.get_protocols(ipv4.ipv4)[0]
                src_ip = ip.src
                dst_ip = ip.dst

                for rule in self.rules:
                    if (src_ip == rule['src_ip'] and
                            dst_ip == rule['dst_ip']):
                        if rule['action'] == 'allow':
                            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
                        elif rule['action'] == 'drop':
                            actions = []
                        else:
                            # Handle other actions as needed
                            pass

                        match = parser.OFPMatch(eth_type=ethernet.ETH_TYPE_IP,
                                                ipv4_src=src_ip,
                                                ipv4_dst=dst_ip)
                        self.add_flow(datapath, 1, match, actions)
        except Exception as e:
            self.logger.error("Error handling packet: %s", e)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, table_id=0)
        datapath.send_msg(mod)

def start_firewall():
    import sys
    from ryu import flags
    from ryu import utils
    import os
    from ryu import version
    from ryu.controller import controller
    from ryu import cfg

    controller_args = ['ryu-manager', 'firewall.py']
    flags.init(sys.argv[1:])
    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.load_apps(controller_args)
    app_mgr.run_apps()
    os._exit(0)

if _name_ == '_main_':
    start_firewall()
