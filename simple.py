from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

servers = [
    {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05"},
    {"ip": "10.0.0.6", "mac": "00:00:00:00:00:06"}
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
        handle_IP_request(packet, event)
        

def handle_arp_request(packet, event):
    global server_index

    arp_packet = packet.find('arp')
    log.info(f"ARP Packet: {arp_packet}")
    
    if arp_packet is None:
        return

    client_ip = str(arp_packet.protosrc)

    if arp_packet.opcode == arp.REQUEST and str(arp_packet.protodst) == virtual_ip:
        
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server

            # Switch to next server
            server_index = (server_index + 1) % len(servers)

            log.info(f"Choosing server {server['ip']} for client {client_ip}")
        else:
            server = client_server_map[client_ip]
            log.info(f"Already mapped {client_ip} to {server['ip']}")

        # Send ARP reply
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr(server["mac"])
        arp_reply.hwdst = arp_packet.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = IPAddr(virtual_ip)
        arp_reply.protodst = arp_packet.protosrc
        
        eth_reply = ethernet()
        eth_reply.src = EthAddr(server["mac"])
        eth_reply.dst = packet.src
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.set_payload(arp_reply)

        message = of.ofp_packet_out()
        message.data = eth_reply.pack()
        message.actions.append(of.ofp_action_output(port=event.port))
        
        log.info(f"Sending ARP reply: {arp_reply}")
        event.connection.send(message)

        # Install flow rule to handle future ARP requests directly
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0806  # ARP packets
        msg.match.nw_dst = IPAddr(virtual_ip)
        msg.actions.append(of.ofp_action_output(port=event.port))
        
        log.info("Installing ARP flow rule")
        event.connection.send(msg)

        

def handle_IP_request(packet, event):
    global server_index

    ip_packet = packet.find('ipv4')
    log.info(f"IP Packet: {ip_packet}")
    
    if ip_packet and ip_packet.dstip == virtual_ip:
        client_ip = str(ip_packet.srcip)
        log.info(f"Client IP = {client_ip}")
        
        log.info(f"Checking to see if client {client_ip} is already mapped")
        
        # Choose a server if not already mapped
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server
            
            # Switch to next server
            server_index = (server_index + 1) % len(servers)
            
            log.info(f"not found, creating a map from {client_ip} to {server['ip']}")
                
        else:
            server = client_server_map[client_ip]
            log.info(f"found map between {client_ip} and {server['ip']}")

        # Add flow rules
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IP packets
        msg.match.nw_src = IPAddr(client_ip)
        msg.match.nw_dst = IPAddr(virtual_ip)

        # Rewrite the destination to the real server IP
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(server['ip'])))
        msg.actions.append(of.ofp_action_output(port=event.port)) 

        log.info(f"Installing flow rule: {client_ip} -> {server['ip']}")
        event.connection.send(msg)

    else:
        log.info("not for me!")

    

def launch():
    log.info("Starting Load Balancer")
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
