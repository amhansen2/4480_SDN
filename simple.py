from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import random

log = core.getLogger()

virtual_ip = IPAddr("10.0.0.10")
servers = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")}
]

server_ports = {}  # Mapping of server IPs to ports
client_server_map = {}
server_index = 0

class LoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.find('arp'):
            self.handle_arp(packet, event)

        elif packet.find('ipv4'):
            self.handle_ip(packet, event)

    def handle_arp(self, packet, event):
        """
        Handle ARP requests for the virtual IP.
        """
        arp_packet = packet.find('arp')
        if not arp_packet:
            return

        if arp_packet and arp_packet.opcode == arp_packet.REQUEST and arp_packet.protodst == virtual_ip:
            global server_index
            server = servers[server_index]
            server_index = (server_index + 1) % len(servers)

            # ✅ Store the server's port
            server_ports[server["ip"]] = event.port  
            log.info(f"[ARP] Storing server {server['ip']} on port {event.port}")

            arp_reply = arp_packet.reply()
            arp_reply.hwsrc = server['mac']
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.protosrc = virtual_ip
            arp_reply.protodst = arp_packet.protosrc

            eth = packet
            eth.payload = arp_reply
            eth.src = server['mac']
            eth.dst = arp_packet.hwsrc

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            log.info(f"Sent ARP reply from {server['ip']} to {arp_packet.protosrc} via port {event.port}")

    def handle_ip(self, packet, event):
        """
        Handle IP packets directed at the virtual IP.
        """
        ip_packet = packet.find('ipv4')

        if ip_packet and ip_packet.dstip == virtual_ip:
            client_ip = str(ip_packet.srcip)

            if client_ip not in client_server_map:
                server = servers[server_index]
                client_server_map[client_ip] = server

                # ✅ Store server port if not already stored
                if server['ip'] not in server_ports:
                    server_ports[server['ip']] = event.port  

                server_index = (server_index + 1) % len(servers)
            else:
                server = client_server_map[client_ip]

            server_ip = server['ip']

            # ✅ Retrieve correct ports
            server_port = server_ports.get(server_ip, event.port)  
            client_port = event.port

            log.info(f"[IP] Client {client_ip} on port {client_port}")
            log.info(f"[IP] Server {server_ip} mapped to port {server_port}")

            # 🚀 Install forward flow rule
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x0800
            msg.match.nw_src = IPAddr(client_ip)
            msg.match.nw_dst = virtual_ip
            msg.match.in_port = client_port  

            msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            msg.actions.append(of.ofp_action_output(port=server_port))  

            log.info(f"[FORWARD] {client_ip} → {server_ip} via port {server_port}")
            event.connection.send(msg)

            # 🚀 Install reverse flow rule
            reverse_msg = of.ofp_flow_mod()
            reverse_msg.match.dl_type = 0x0800
            reverse_msg.match.nw_src = server_ip
            reverse_msg.match.nw_dst = IPAddr(client_ip)
            reverse_msg.match.in_port = server_port  

            reverse_msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
            reverse_msg.actions.append(of.ofp_action_output(port=client_port))  

            log.info(f"[REVERSE] {server_ip} → {client_ip} via port {client_port}")
            event.connection.send(reverse_msg)

def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
