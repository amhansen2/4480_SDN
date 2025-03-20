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

    # must match the virtual IP
    if arp_packet.opcode == arp.REQUEST and str(arp_packet.protodst) == virtual_ip:
        
        # not already in map, choose a server
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server
            log.info(f"Choosing server {server['ip']} for client {client_ip}")
            
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
        arp_reply.hwsrc = EthAddr(server["mac"]) #server mac we chose
        arp_reply.hwdst = arp_packet.hwsrc #client mac(where we received the request from)
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = IPAddr(virtual_ip) #looks like this is from virtual server IP
        arp_reply.protodst = arp_packet.protosrc #client IP

        log.info(f"ARP REPLY: pretending virtual server is {arp_reply.hwsrc}")
        
        eth_reply = ethernet()
        eth_reply.src = EthAddr(server["mac"])
        eth_reply.dst = packet.src #original packet
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.set_payload(arp_reply)

        message = of.ofp_packet_out()
        message.data = eth_reply.pack()
        message.actions.append(of.ofp_action_output(port=event.port))
        
        log.debug(f"Sending message: {message}")
        event.connection.send(message)
        

def handle_IP_request(packet, event):
    global server_index

    ip_packet = packet.find('ipv4')
    log.info(f"IP Packet: {ip_packet}")
    
   
    if ip_packet.dstip == virtual_ip:
        client_ip = str(ip_packet.srcip)
        log.info(f"Client IP = {client_ip}")
        
        log.info(f"Checking to see if client {client_ip} is already mapped")
        
        # Choose a server if not already mapped
        if client_ip not in client_server_map:
            server = servers[server_index]
            client_server_map[client_ip] = server
            
            # Switch to next server
            if server_index == 0:
                server_index = 1
            else:
                server_index = 0
                
            log.info(f"not found, creating a map from {client_ip} to {server['ip']}")
                
        else:
            server = client_server_map[client_ip]
            log.info(f"found map between {client_ip} and {server['ip']}")
            
            
        #add flow mod to switch
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(server["mac"])))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(virtual_ip)))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(client_ip)))
        msg.actions.append(of.ofp_action_output(port=server["port"]))
        
        log.debug(f"Sending flow mod: {msg}")
        event.connection.send(msg) 
        
        
        
            
    else:
        log.info("not for me!")
    

def launch():
    log.info("Starting Load Balancer")
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
