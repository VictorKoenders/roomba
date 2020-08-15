#[derive(Debug, PartialEq, Eq)]
pub enum RoombaPacket {
    ErrorPleasePressTheHomeButton, // 0x3: Please press the home button
    Unknown(u8, Vec<u8>),          // Unknown, please report this if you get it!
    Password(StringOrBlob),        // password
}

pub enum RequestPacket {
    Password,
}

impl RequestPacket {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            RequestPacket::Password => [0xf0, 0x05, 0xef, 0xcc, 0x3b, 0x29, 0x00].to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StringOrBlob {
    String(String),
    Blob(Vec<u8>, std::str::Utf8Error),
}

impl StringOrBlob {
    pub fn expect_string(self) -> String {
        match self {
            StringOrBlob::String(s) => s,
            StringOrBlob::Blob(blob, err) => {
                panic!("Invalid string: {:?}\n{:?}", err, blob);
            }
        }
    }
}

impl StringOrBlob {
    pub fn from_slice(slice: &[u8]) -> Self {
        match std::str::from_utf8(slice) {
            Ok(str) => Self::String(str.to_string()),
            Err(e) => Self::Blob(slice.to_owned(), e),
        }
    }
}

impl RoombaPacket {
    pub fn from_type(type_num: u8, data: &[u8]) -> Self {
        match type_num {
            0 => Self::Password(StringOrBlob::from_slice(data)),
            3 => Self::ErrorPleasePressTheHomeButton,
            _ => Self::Unknown(type_num, data.to_vec()),
        }
    }
}

pub struct RoombaPacketIterator<S> {
    stream: S,
}

impl<S> RoombaPacketIterator<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: std::io::Write> RoombaPacketIterator<S> {
    pub fn send(&mut self, req: RequestPacket) -> std::io::Result<()> {
        let bytes = req.to_bytes();
        log::trace!("Sending {:?}", bytes);
        self.stream.write_all(&bytes).map(|_| ())
    }
}

impl<S: std::io::Read> RoombaPacketIterator<S> {
    pub fn next(&mut self) -> std::io::Result<RoombaPacket> {
        let mut buff = [0u8; 1024];
        loop {
            let len = self.stream.read(&mut buff)?;
            if len == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }

            // Packets seem to come in 2 flavors:
            // 1. The roomba sends 2 bytes [240, <LEN>], then sends another packet with <LEN> bytes.
            // 2. The roomba sends it all at once.
            if len == 2 {
                // Flavor 1
                // packet should be [240, <len>]
                // Next packet is the actual buffer
                if buff[0] != 240 {
                    print_unexpected_protocol(format!(
                        "Expected [240, {}] got {:?}",
                        buff[1],
                        &buff[..len]
                    ));
                }
                let expected_len = buff[1] as usize;
                let len = self.stream.read(&mut buff)?;
                if len != expected_len {
                    log::warn!(
                        "Expected {} bytes from the 2-byte header, got {} bytes",
                        expected_len,
                        len
                    );
                }
                if len >= 4 && &buff[..4] != &[239, 204, 59, 41] {
                    print_unexpected_protocol(format!(
                        "Expected [239, 204, 59, 41], found {:?}",
                        &buff[..4]
                    ));
                }
                if len >= 5 {
                    let num = buff[4];
                    return Ok(RoombaPacket::from_type(num, &buff[5..len]));
                } else {
                    log::error!(
                        "Expected at least 5 bytes, got {} ({:?})",
                        len,
                        &buff[..len]
                    );
                    continue;
                }
            }
            // Flavor 2
            // TODO: wait for cecton's data
            log::info!("Packet flavor 2: {:?}", &buff[..len]);
        }
    }
}

fn print_unexpected_protocol(f: impl std::fmt::Display) {
    // Make sure we send this message only once, and not spam the user
    use std::sync::atomic::{AtomicBool, Ordering};
    static HAS_SEND_MESSAGE: AtomicBool = AtomicBool::new(false);
    if HAS_SEND_MESSAGE.swap(true, Ordering::Relaxed) {
        return;
    }

    println!(
        "Hello, sorry to bother you, but your protocol does not seem to match what we expected"
    );
    println!(
        "We're reverse engineering the roomba protocol and your roomba does something different"
    );
    println!("{}", f);
    println!("Please report this at https://github.com/cecton/roomba/issue so we can figure out how to support your roomba better");
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::VecDeque;

    struct PacketBuffer {
        read_buffer: VecDeque<Vec<u8>>,
        write_buffer: Vec<Vec<u8>>,
    }
    impl std::io::Read for PacketBuffer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let packet = self.read_buffer.pop_front().unwrap();
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }
    impl std::io::Write for PacketBuffer {
        fn write(&mut self, buff: &[u8]) -> std::io::Result<usize> {
            self.write_buffer.push(buff.to_vec());
            Ok(buff.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trangar_roomba_protocol() {
        let buffer = PacketBuffer {
            read_buffer: vec![
                vec![240, 5],
                vec![239, 204, 59, 41, 3],
                vec![240, 35],
                vec![
                    239, 204, 59, 41, 0, 58, 49, 58, 49, 53, 56, 50, 56, 57, 50, 56, 52, 55, 58,
                    49, 98, 54, 119, 69, 86, 121, 49, 52, 121, 57, 100, 112, 118, 105, 109,
                ],
            ]
            .into_iter()
            .collect(),
            write_buffer: Vec::new(),
        };

        let mut iterator = RoombaPacketIterator::new(buffer);

        assert_eq!(
            iterator.next().unwrap(),
            RoombaPacket::ErrorPleasePressTheHomeButton
        );
        assert!(iterator.stream().write_buffer.is_empty());

        iterator.send(RequestPacket::Password).unwrap();
        assert_eq!(
            iterator.next().unwrap(),
            RoombaPacket::Password(StringOrBlob::String(
                ":1:1582892847:1b6wEVy14y9dpvim".to_string()
            ))
        );
        assert_eq!(
            iterator.stream().write_buffer[0],
            RequestPacket::Password.to_bytes()
        );
    }
}
