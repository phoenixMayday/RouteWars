use pnet::packet::Packet;
use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::io::Result;
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;
use rand::{Rng, thread_rng};
use rand::rngs::ThreadRng;

mod dns;
use dns::{decode_qname, DnsDecodeError};

const IGNORE_DNS_PROBABILITY: f64 = 0.95;

fn main() -> Result<()> {
    // Define your blocklist of domain names
    let blocklist = vec![
        "example.com",
    ];
    let blocklist_arc = Arc::new(blocklist);
    
    let mut queue = Queue::open()?;
    queue.bind(0)?;
    let queue_arc = Arc::new(Mutex::new(queue));

    let num_workers = 4;
    let pool = ThreadPool::new(num_workers);
    
    // Create thread-local RNGs instead of sharing one
    // Each worker will create its own RNG when it starts

    loop {
        let queue_clone = Arc::clone(&queue_arc);
        let blocklist_clone = Arc::clone(&blocklist_arc);

        pool.execute(move || {
            // Create thread-local RNG
            let mut rng = thread_rng();
            
            // Get the next packet
            let mut msg = {
                let mut locked_queue = queue_clone.lock().unwrap();
                locked_queue.recv().unwrap()
            };

            let packet_data = msg.get_payload();
            let mut verdict = Verdict::Accept; // Default to accepting the packet

            if let Some(ipv4) = Ipv4Packet::new(packet_data) {
                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            // Check if destination port is 53 (DNS)
                            if udp.get_destination() == 53 {
                                if !rng.gen_bool(IGNORE_DNS_PROBABILITY) {
                                    // Decode DNS QNAME
                                    let mut qname_buffer = [0u8; 256];
                                    if let Ok(len) = decode_qname(udp.payload(), &mut qname_buffer) {
                                        if let Ok(qname) = std::str::from_utf8(&qname_buffer[..len]) {
                                            // Check if the QNAME is in the blocklist
                                            if blocklist_clone.iter().any(|blocked| {
                                                qname == *blocked || qname.ends_with(&format!(".{}", blocked))
                                            }) {
                                                verdict = Verdict::Drop;
                                            }
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
            let mut locked_queue = queue_clone.lock().unwrap();
            if let Err(e) = locked_queue.verdict(msg) {
                eprintln!("Error setting verdict: {}", e);
            }
        });
    }
}
