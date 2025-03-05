from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def _handle_PacketIn(event):
    log.info(f"Packet received from port {event.port}, flooding...")
    
    # send packet to all ports (flooding)
    msg = of.ofp_packet_out()
    msg.data = event.ofp 
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def launch():
    log.info("Basic Forwarding Controller Started")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
