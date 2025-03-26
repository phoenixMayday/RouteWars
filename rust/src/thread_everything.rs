use nfq::{Queue, Verdict};
use std::io::Result;
use std::thread;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    let mut queue = Queue::open()?; 
    queue.bind(0)?;
    let queue_arc = Arc::new(Mutex::new(queue));

    loop {
        let mut msg = {
            let mut locked_queue = queue_arc.lock().unwrap();
            locked_queue.recv()?
        };
        let queue_clone = Arc::clone(&queue_arc);

        thread::spawn(move || {
            msg.set_verdict(Verdict::Accept);
            let mut locked_queue = queue_clone.lock().unwrap();
            if let Err(e) = locked_queue.verdict(msg) {
                eprintln!("Error setting verdict: {}", e);
            }
        });
    }
    Ok(())
}
