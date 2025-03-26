use nfq::{Queue, Verdict};
use std::io::Result;
use std::thread;
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;

fn main() -> Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;
    let queue_arc = Arc::new(Mutex::new(queue));

    let num_workers = 4;
    let pool = ThreadPool::new(num_workers);

    loop {
        let queue_clone = Arc::clone(&queue_arc);

        pool.execute(move || {
            let mut msg = {
                let mut locked_queue = queue_clone.lock().unwrap();
                locked_queue.recv().unwrap()
            };
            msg.set_verdict(Verdict::Accept);
            let mut locked_queue = queue_clone.lock().unwrap();
            if let Err(e) = locked_queue.verdict(msg) {
                eprintln!("Error setting verdict: {}", e);
            }
        });
    }
    Ok(())
}
