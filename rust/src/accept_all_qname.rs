use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::io;

mod dns;
use dns::{decode_qname, DnsDecodeError};

fn main() -> io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;

    loop {
        let mut msg = queue.recv()?;
        let packet_data = msg.get_payload();

        if let Some(ipv4) = Ipv4Packet::new(packet_data) {
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        println!(
                            "UDP Packet - Source Port: {}, Destination Port: {}",
                            udp.get_source(),
                            udp.get_destination()
                        );

                        // Check if destination port is 53 (DNS)
                        if udp.get_destination() == 53 {
                            println!("UDP DNS packet handled.");

                            // Decode DNS QNAME
                            let mut qname_buffer = [0u8; 256]; // Adjust size as needed
                            match decode_qname(udp.payload(), &mut qname_buffer) {
                                Ok(len) => {
                                    let qname = std::str::from_utf8(&qname_buffer[..len])
                                        .unwrap_or("[invalid utf8]");
                                    println!("DNS Query: {}", qname);
                                }
                                Err(e) => {
                                    println!("Failed to decode DNS QNAME: {}", e);
                                }
                            }

                        } else {
                            println!("Data packet handled (UDP, non-DNS).");
                        }
                    } else {
                        println!("Data packet handled (UDP parsing failed).");
                    }
                }
                _ => println!("Data packet handled (non-UDP)."),
            }
        } else {
            println!("Data packet handled (IPv4 parsing failed).");
        }

        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}
