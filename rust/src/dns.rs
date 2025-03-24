use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum DnsDecodeError {
    OutOfBounds,
    BufferOverflow,
}

impl fmt::Display for DnsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsDecodeError::OutOfBounds => write!(f, "Invalid packet: out of bounds"),
            DnsDecodeError::BufferOverflow => write!(f, "Buffer overflow"),
        }
    }
}

impl Error for DnsDecodeError {}

pub fn decode_qname(payload: &[u8], buffer: &mut [u8]) -> Result<usize, DnsDecodeError> {
    let mut index = 12; // skip DNS header (12 bytes)
    let mut buffer_index = 0;

    loop {
        if index >= payload.len() {
            return Err(DnsDecodeError::OutOfBounds);
        }

        let length = payload[index] as usize; // length of each label
        if length == 0 {
            break; // end of QNAME
        }

        // Check if adding the length and '.' would exceed buffer size
        if buffer_index + length + 1 > buffer.len() {
            return Err(DnsDecodeError::BufferOverflow);
        }

        if buffer_index > 0 {
            buffer[buffer_index] = b'.';
            buffer_index += 1;
        }
        index += 1;

        for _i in 0..length {
            if index >= payload.len() {
                return Err(DnsDecodeError::OutOfBounds);
            }
            buffer[buffer_index] = payload[index];
            buffer_index += 1;
            index += 1;
        }
    }

    Ok(buffer_index)
}
