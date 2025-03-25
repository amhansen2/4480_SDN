from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

log = core.getLogger()

# Define the server IPs, MAC addresses, and manual port assignments
servers = [
    {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "port": 5},
    {"ip": "10.0.0.6", "mac": "00:00:00:00:00:06", "port": 6}
]
virtual_ip = "10.0.0.10"
server_index = 0
client_server_map = {}

# Manually set the port mappings (based on Mininet or your topology)
hosts = [
    {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1},
    {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2},
    {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3},
    {"ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "port": 4}
]

def handle_packet_in(event):
    packet = event.parsed
    
    if not packet.parsed:
        return

    if packet.type == packet.ARP_TYPE:
        handle_arp_request(packet, event)
        
    elif packet.type == packet.IP_TYPE:
        handle_IP_request(packet, event)


def handle_arp_request(packet, event):
    global server_index

    arp_packet = packet.find('arp')
    if arp_packet is None:
        return
    
    log.info(f"ARP Packet: {arp_packet}")

    client_ip = str(arp_packet.protosrc)
    log.info(f"Source of the arp is {client_ip}")
    
    #If the arp is ffrom the server
    if str(arp_packet.protosrc) in [server["ip"] for server in servers]:
        log.info(f"ARP request from server: {arp_packet.protosrc} → {arp_packet.protodst}")
        
        # ✅ Fixed dictionary access
        server = next((server for server in servers if server["ip"] == arp_packet.protosrc), None)
        host = next((host for host in hosts if host["ip"] == arp_packet.protodst), None)

        if not server or not host:
            log.warning("Server or host not found.")
            return
        
       # Construct the ARP reply for the server
        arp_return = arp()
        arp_return.hwsrc = EthAddr(host["mac"])   # Set MAC to 00:00:00:00:00:01
        arp_return.hwdst = arp_packet.hwsrc               # Destination MAC is the sender's MAC
        arp_return.opcode = arp.REPLY
        arp_return.protosrc = IPAddr(host["ip"])          # Source IP is 10.0.0.1
        arp_return.protodst = arp_packet.protosrc         # Destination IP is the sender's IP (10.0.0.5)

        eth_return = ethernet()
        eth_return.src = EthAddr(host["mac"])     # Use the same MAC as ARP source
        eth_return.dst = arp_packet.hwsrc                 # Send to the requester
        eth_return.type = ethernet.ARP_TYPE
        eth_return.set_payload(arp_return)

        message_return = of.ofp_packet_out()
        message_return.data = eth_return.pack()
        message_return.actions.append(of.ofp_action_output(port=event.port))  # Send out the port the request came from

        
        event.connection.send(message_return)
        log.info(f"Sending ARP reply to server: {arp_return.protosrc} → {arp_return.protodst}")
        return

    # else this is from a client
    if arp_packet.opcode == arp.REQUEST and str(arp_packet.protodst) == virtual_ip:
        
        # see if we already have a mapping
        if client_ip not in client_server_map:
            server = servers[server_index]
            log.info(f"Selecting server: {server}")

            client_server_map[client_ip] = server

            # Switch to next server (round-robin)
            server_index = (server_index + 1) % len(servers)
        else:
            server = client_server_map[client_ip]
            log.info(f"Already mapped to server: {server}")

        # Construct the ARP reply with the corrected source and target
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr(server["mac"])
        arp_reply.hwdst = arp_packet.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = arp_packet.protodst  # Server IP (target)
        arp_reply.protodst = arp_packet.protosrc  # Client IP (source)

        eth_reply = ethernet()
        eth_reply.src = EthAddr(server["mac"])
        eth_reply.dst = packet.src
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.set_payload(arp_reply)
        
        message = of.ofp_packet_out()
        message.data = eth_reply.pack()
        ##message.in_port = event.port
        message.actions.append(of.ofp_action_output(port=event.port))
        
        event.connection.send(message)
        log.info(f"Sending ARP reply to client: {arp_reply.protosrc} → {arp_reply.protodst}")
        


def handle_IP_request(packet, event):
    global server_index
    ip_packet = packet.find('ipv4')
    log.info(f"IPV4 Packet: {ip_packet}")

    if ip_packet and ip_packet.dstip == virtual_ip:
        client_ip = str(ip_packet.srcip)

        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server

            # Switch to the next server (round-robin)
            server_index = (server_index + 1) % len(servers)

        else:
            server = client_server_map[client_ip]

        server_ip = server['ip']
        server_port = server["port"]  # Use the port that is associated with the server

        # ✅ Fixed dictionary access
        client_host = next((host for host in hosts if host["ip"] == client_ip), None)

        if not client_host:
            log.warning(f"No matching client host for {client_ip}")
            return

        client_port = client_host["port"]  # Use the port that is associated with the client

        # Add forward flow (client → server)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = IPAddr(virtual_ip)
        msg.match.in_port = client_port  

        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(server_ip)))
        msg.actions.append(of.ofp_action_output(port=server_port))  
        
        log.info(f"Forward flow: {client_ip} → {server_ip} via {server_port}")
        event.connection.send(msg)

        # Add reverse flow (server → client)
        reverse_msg = of.ofp_flow_mod()
        reverse_msg.match.dl_type = 0x0800
        reverse_msg.match.nw_src = IPAddr(server_ip)
        reverse_msg.match.nw_dst = IPAddr(client_ip)
        reverse_msg.match.in_port = server_port  

        reverse_msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virtual_ip)))
        reverse_msg.actions.append(of.ofp_action_output(port=client_port))  
        
        log.info(f"Reverse flow: {server_ip} → {client_ip} via {client_port}")
        event.connection.send(reverse_msg)


def launch():
    log.info("Starting Load Balancer")
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
