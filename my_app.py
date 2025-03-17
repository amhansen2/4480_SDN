servers = [
    {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05"},
    {"ip": "10.0.0.6", "mac": "00:00:00:00:00:06"}
]
server_index = 0
client_server_mapping = {}

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        return

    if packet.type == packet.ARP_TYPE:
        handle_arp_request(packet, event)
        return

    if packet.type == packet.IP_TYPE:
        handle_ip_packet(packet, event)
        return

def handle_arp_request(packet, event):
    global server_index

    arp_pkt = packet.find('arp')
    if arp_pkt is None or arp_pkt.opcode != arp.REQUEST:
        return

    client_ip = str(arp_pkt.protosrc)
    virtual_ip = "10.0.0.10"

    if str(arp_pkt.protodst) == virtual_ip:
        if client_ip not in client_server_mapping:
            assigned_server = servers[server_index]
            client_server_mapping[client_ip] = assigned_server
            server_index = (server_index + 1) % len(servers)
        else:
            assigned_server = client_server_mapping[client_ip]

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

        log.info(f"Assigned {client_ip} -> {assigned_server['ip']} ({assigned_server['mac']})")

def handle_ip_packet(packet, event):
    ip_pkt = packet.find('ipv4')
    if not ip_pkt:
        return

    client_ip = str(ip_pkt.srcip)
    virtual_ip = "10.0.0.10"

    if ip_pkt.dstip == virtual_ip:
        if client_ip in client_server_mapping:
            backend = client_server_mapping[client_ip]
        else:
            backend = servers[server_index]
            client_server_mapping[client_ip] = backend
            global server_index
            server_index = (server_index + 1) % len(servers)

        log.info(f"Redirecting {client_ip} -> {backend['ip']}")

        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = virtual_ip
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(backend["ip"])))
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

def launch():
    log.info("Controller Started")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
