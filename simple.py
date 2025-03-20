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
       log.info("IP Packet")
        

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

        # #send ARP response
        # arp_reply = arp()
        # arp_reply.hwsrc = EthAddr(server["mac"])
        # arp_reply.hwdst = arp_packet.hwsrc
        # arp_reply.opcode = arp.REPLY
        # arp_reply.protosrc = IPAddr(virtual_ip)
        # arp_reply.protodst = arp_packet.protosrc

        # log.info(f"ARP REPLY: mac address for virtual server is {arp_reply.hwsrc}")
        # eth_reply = ethernet()
        # eth_reply.src = EthAddr(server["mac"])
        # eth_reply.dst = packet.src
        # eth_reply.type = ethernet.ARP_TYPE
        # eth_reply.set_payload(arp_reply)

        # message = of.ofp_packet_out()
        # message.data = eth_reply.pack()
        # message.actions.append(of.ofp_action_output(port=server["port"]))
        
        # log.debug(f"Sending flow mod: {message}")
        # event.connection.send(message)


def launch():
    log.info("Starting Load Balancer")
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
