use std::str;
use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    InvalidLabel,
    BufferOverflow,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::InvalidLabel => write!(f, "Invalid DNS label"),
            DnsError::BufferOverflow => write!(f, "Buffer overflow"),
        }
    }
}

pub fn decode_qname(payload: &[u8], buffer: &mut [u8]) -> Result<String, DnsError> {
    let mut pos = 0;
    let mut buf_pos = 0;

    loop {
        if pos >= payload.len() {
            return Err(DnsError::InvalidLabel);
        }

        let len = payload[pos] as usize;
        pos += 1;

        if len == 0 {
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Handle DNS compression (not implemented here)
            return Err(DnsError::InvalidLabel);
        }

        if buf_pos + len + 1 > buffer.len() {
            return Err(DnsError::BufferOverflow);
        }

        buffer[buf_pos..buf_pos + len].copy_from_slice(&payload[pos..pos + len]);
        buf_pos += len;
        buffer[buf_pos] = b'.';
        buf_pos += 1;
        pos += len;
    }

    if buf_pos == 0 {
        return Ok(String::new());
    }

    buffer[buf_pos - 1] = 0; // Replace the last dot with a null terminator
    let qname = unsafe { str::from_utf8_unchecked(&buffer[..buf_pos - 1]) };
    Ok(qname.to_string())
}
