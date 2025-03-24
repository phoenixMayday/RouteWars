use nfq::{Queue, Verdict};

fn main() -> std::io::Result<()> {
   let mut queue = Queue::open()?;
   queue.bind(0)?;
   loop {
       let mut msg = queue.recv()?;
       msg.set_verdict(Verdict::Accept);
       queue.verdict(msg)?;
   }
   Ok(())
}
