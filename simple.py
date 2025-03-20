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
server_ports = {}  

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
    if arp_packet is None:
        return

    client_ip = str(arp_packet.protosrc)

    if arp_packet.opcode == arp.REQUEST and str(arp_packet.protodst) == virtual_ip:
        
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server

            # Store the server port
            server_ports[server['ip']] = event.port  
            
            # Switch to next server
            server_index = (server_index + 1) % len(servers)

        else:
            server = client_server_map[client_ip]

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
        
        event.connection.send(message)


def handle_IP_request(packet, event):
    ip_packet = packet.find('ipv4')
    
    if ip_packet and ip_packet.dstip == virtual_ip:
        client_ip = str(ip_packet.srcip)

        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server

            # Store server port only if not already mapped
            if server['ip'] not in server_ports:
                server_ports[server['ip']] = event.port  

            server_index = (server_index + 1) % len(servers)

        else:
            server = client_server_map[client_ip]

        server_ip = server['ip']

        #  Use stored ports
        server_port = server_ports.get(server_ip, event.port)  
        client_port = event.port

        # 💡 Add forward rule (client → server)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = IPAddr(client_ip)
        msg.match.nw_dst = IPAddr(virtual_ip)
        msg.match.in_port = client_port  

        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(server_ip)))
        msg.actions.append(of.ofp_action_output(port=server_port))  
        
        log.info(f"Forward flow: {client_ip} → {server_ip} via {server_port}")
        event.connection.send(msg)

        # 💡 Add reverse rule (server → client)
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
