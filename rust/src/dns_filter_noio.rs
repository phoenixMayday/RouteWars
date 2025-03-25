use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::io;

mod dns;
use dns::{decode_qname, DnsDecodeError};

fn main() -> io::Result<()> {
    // Define your blocklist of domain names
    let blocklist = vec![
        "example.com",
    ];

    let mut queue = Queue::open()?;
    queue.bind(0)?;

    loop {
        let mut msg = queue.recv()?;
        let packet_data = msg.get_payload();
        let mut verdict = Verdict::Accept; // Default to accepting the packet

        if let Some(ipv4) = Ipv4Packet::new(packet_data) {
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        // Check if destination port is 53 (DNS)
                        if udp.get_destination() == 53 {
                            // Decode DNS QNAME
                            let mut qname_buffer = [0u8; 256];
                            if let Ok(len) = decode_qname(udp.payload(), &mut qname_buffer) {
                                if let Ok(qname) = std::str::from_utf8(&qname_buffer[..len]) {
                                    // Check if the QNAME is in the blocklist
                                    if blocklist.iter().any(|&blocked| {
                                        qname == blocked || qname.ends_with(&format!(".{}", blocked))
                                    }) {
                                        verdict = Verdict::Drop;
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
}
