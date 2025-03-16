use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::io;

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
