from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.util import dpid_to_str
import random

log = core.getLogger()

# Virtual IP and server IPs
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
SERVER_MACS = {
    IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
    IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06"),
}

# Round-robin counter
counter = 0

class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load Balancer Initialized: %s", dpid_to_str(connection.dpid))

    def pick_server(self):
        """Round-robin server selection"""
        global counter
        server = SERVERS[counter % len(SERVERS)]
        counter += 1
        return server

    def install_flow(self, in_port, src_ip, dst_ip, dst_mac, out_port):
        """Install bidirectional OpenFlow rules"""
        msg = of.ofp_flow_mod()
        msg.match.in_port = in_port
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = src_ip
        msg.match.nw_dst = VIRTUAL_IP

        msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))

        self.connection.send(msg)

        # Reverse flow (server → client)
        msg_rev = of.ofp_flow_mod()
        msg_rev.match.in_port = out_port
        msg_rev.match.dl_type = 0x0800
        msg_rev.match.nw_src = dst_ip
        msg_rev.match.nw_dst = src_ip

        msg_rev.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg_rev.actions.append(of.ofp_action_dl_addr.set_src(ETHER_BROADCAST))
        msg_rev.actions.append(of.ofp_action_output(port=in_port))

        self.connection.send(msg_rev)

    def _handle_PacketIn(self, event):
        """Handle incoming packets"""
        packet = event.parsed
        in_port = event.port

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle ARP Requests
        if packet.type == ethernet.ARP_TYPE:
            arp_packet = packet.payload

            if arp_packet.opcode == arp.REQUEST and arp_packet.protodst == VIRTUAL_IP:
                server_ip = self.pick_server()
                server_mac = SERVER_MACS[server_ip]

                # Respond with server MAC
                arp_reply = arp()
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = arp_packet.protosrc

                eth = ethernet()
                eth.type = ethernet.ARP_TYPE
                eth.src = server_mac
                eth.dst = arp_packet.hwsrc
                eth.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)

                log.info(f"ARP Response: {VIRTUAL_IP} → {server_ip} ({server_mac})")

                # Install flow rules
                self.install_flow(
                    in_port=in_port,
                    src_ip=arp_packet.protosrc,
                    dst_ip=server_ip,
                    dst_mac=server_mac,
                    out_port=event.port + 4  # Adjust ports based on your topology
                )

def launch():
    """Start the Load Balancer application"""
    def start(event):
        log.info("Starting Load Balancer")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start)
