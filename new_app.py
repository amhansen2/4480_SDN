from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

servers = [
    {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "port": 1},
    {"ip": "10.0.0.6", "mac": "00:00:00:00:00:06", "port": 2}
]

virtual_ip = "10.0.0.10"
server_index = 0
client_server_map = {}

def handle_packet_in(event):
    packet = event.parsed
    log.info(f"Recieved Packet: {packet}")
    
    if not packet.parsed:
        return

    if packet.type == packet.ARP_TYPE:
        handle_arp_request(packet, event)
        
    elif packet.type == packet.IP_TYPE:
        handle_ip_packet(packet, event)
        

def handle_arp_request(packet, event):
    global server_index

    arp_packet = packet.find('arp')
    log.info(f"ARP Packet: {arp_packet}")
    
    if arp_packet is None:
        return

    client_ip = str(arp_packet.protosrc)

    # must match the virtual IP
    if arp_packet.opcode == arp.REQUEST and str(arp_packet.protodst) == virtual_ip:
        
        # not already in map, choose a server
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server
            log.info(f"Creating a map from {client_ip} to {server['ip']}")
            
            # switch next server index
            if server_index == 0:
                server_index = 1
            else:
                server_index = 0
            
        # already in map   
        else:
            server = client_server_map[client_ip]
            log.info(f"Already mapped {client_ip} to {server['ip']}")

        #send ARP response
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr(server["mac"])
        arp_reply.hwdst = arp_packet.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = IPAddr(virtual_ip)
        arp_reply.protodst = arp_packet.protosrc

        log.info(f"ARP REPLY: mac address for virtual server is {arp_reply.hwsrc}")
        eth_reply = ethernet()
        eth_reply.src = EthAddr(server["mac"])
        eth_reply.dst = packet.src
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.set_payload(arp_reply)

        message = of.ofp_packet_out()
        message.data = eth_reply.pack()
        message.actions.append(of.ofp_action_output(port=server["port"]))
        
        log.debug(f"Sending flow mod: {message}")
        event.connection.send(message)



def handle_ip_packet(packet, event):
    global server_index

    ip_packet = packet.find('ipv4')
    log.info(f"IP Packet: {ip_packet}")
    
    if not ip_packet:
        return

    client_ip = str(ip_packet.srcip)
    
    # received packet for the virtual IP
    if ip_packet.dstip == virtual_ip:
        
        # Choose a server if not already mapped
        if client_ip not in client_server_map:
            backend = servers[server_index]
            client_server_map[client_ip] = backend
            
            # Switch to next server
            if server_index == 0:
                server_index = 1
            else:
                server_index = 0
                
            log.info(f"Creating a map from {client_ip} to {backend['ip']}")
                
        else:
            backend = client_server_map[client_ip]
            log.info(f"already in map... sending {client_ip} to {backend['ip']}")

        # client to server flow rule
        message = of.ofp_flow_mod()
        message.match.dl_type = ethernet.IP_TYPE
        message.match.nw_src = IPAddr(client_ip)
        message.match.nw_dst = IPAddr(virtual_ip)
        # Rewrite IP and MAC
        message.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(backend['ip'])))
        message.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(backend['mac'])))
        # Send to correct server port
        message.actions.append(of.ofp_action_output(port=backend["port"]))
        log.debug(f"Sending flow mod: {message}")
        event.connection.send(message)

        # server to client flow rule
        reverse_message = of.ofp_flow_mod()
        reverse_message.match.dl_type = ethernet.IP_TYPE
        reverse_message.match.nw_src = IPAddr(backend['ip'])
        reverse_message.match.nw_dst = IPAddr(client_ip)
        # Rewrite source IP and MAC
        reverse_message.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virtual_ip)))
        reverse_message.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:10")))  # Virtual MAC
        # Send back to client
        reverse_message.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(reverse_message)

        log.info(f"Reverse flow rule set: {backend['ip']} → {client_ip}")


def launch():
    log.info("Starting Load Balancer")
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
