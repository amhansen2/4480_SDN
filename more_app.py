from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp, ipv4

log = core.getLogger()

# Server pool
servers = [
    {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05"},
    {"ip": "10.0.0.6", "mac": "00:00:00:00:00:06"}
]

virtual_ip = "10.0.0.10"
server_index = 0
client_server_mapping = {}

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        return

    if packet.type == packet.ARP_TYPE:
        handle_arp_request(packet, event)
    elif packet.type == packet.IP_TYPE:
        handle_ip_packet(packet, event)

def handle_arp_request(packet, event):
    global server_index

    arp_pkt = packet.find('arp')
    if arp_pkt is None:
        return

    client_ip = str(arp_pkt.protosrc)

    # Handle only ARP requests for the virtual IP
    if arp_pkt.opcode == arp.REQUEST and str(arp_pkt.protodst) == virtual_ip:
        if client_ip not in client_server_mapping:
            assigned_server = servers[server_index]
            client_server_mapping[client_ip] = assigned_server
            server_index = (server_index + 1) % len(servers)
        else:
            assigned_server = client_server_mapping[client_ip]

        log.info(f"ARP Request from {client_ip}: Assigning {assigned_server['ip']}")

        # Send ARP response
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr(assigned_server["mac"])
        arp_reply.hwdst = arp_pkt.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = IPAddr(virtual_ip)
        arp_reply.protodst = arp_pkt.protosrc

        eth_reply = ethernet()
        eth_reply.src = EthAddr(assigned_server["mac"])
        eth_reply.dst = packet.src
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.set_payload(arp_reply)

        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

def handle_ip_packet(packet, event):
    global server_index

    ip_pkt = packet.find('ipv4')
    if not ip_pkt:
        return

    client_ip = str(ip_pkt.srcip)
    
    # Handle requests to the virtual IP
    if ip_pkt.dstip == virtual_ip:
        if client_ip not in client_server_mapping:
            backend = servers[server_index]
            client_server_mapping[client_ip] = backend
            server_index = (server_index + 1) % len(servers)
        else:
            backend = client_server_mapping[client_ip]

        log.info(f"Redirecting {client_ip} -> {backend['ip']}")

        # Flow rule: Client → Server
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = IPAddr(client_ip)
        msg.match.nw_dst = IPAddr(virtual_ip)

        # Rewrite IP and MAC
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(backend['ip'])))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(backend['mac'])))
        
        # Send to correct server port
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

        # Flow rule: Server → Client (Reverse path)
        reverse_msg = of.ofp_flow_mod()
        reverse_msg.match.dl_type = ethernet.IP_TYPE
        reverse_msg.match.nw_src = IPAddr(backend['ip'])
        reverse_msg.match.nw_dst = IPAddr(client_ip)

        # Rewrite source IP and MAC
        reverse_msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virtual_ip)))
        reverse_msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:10")))  # Virtual MAC

        # Send back to client
        reverse_msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(reverse_msg)

        log.info(f"Reverse flow rule set: {backend['ip']} → {client_ip}")

def launch():
    log.info("Starting SDN Load Balancer")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
