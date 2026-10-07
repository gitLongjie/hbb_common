use bytes::BytesMut;
use std::io::{Error, ErrorKind};

const MAGIC: &[u8; 4] = b"RDPX";
const VERSION: u8 = 2;
const PAYLOAD_PROTOBUF: u8 = 1;
const HEADER_LEN: usize = 7;

/// The private wire envelope used by the forked client and server.
///
/// This is an application protocol, not RustDesk's content framing.  The
/// transport supplies the frame boundary, so this envelope deliberately has no
/// second plaintext payload length.  Callers encrypt the complete envelope
/// before it reaches an authenticated transport; consequently the magic,
/// version, kind, and protobuf bytes are hidden on secured streams.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.push(0);
    frame.push(PAYLOAD_PROTOBUF);
    frame.extend_from_slice(payload);
    frame
}

pub fn decode(mut frame: BytesMut) -> Result<BytesMut, Error> {
    if frame.len() < HEADER_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "private protocol frame is shorter than its header",
        ));
    }
    if &frame[..MAGIC.len()] != MAGIC {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported private protocol",
        ));
    }
    if frame[4] != VERSION || frame[5] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported private protocol version",
        ));
    }
    if frame[6] != PAYLOAD_PROTOBUF {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported private protocol payload kind",
        ));
    }
    Ok(frame.split_off(HEADER_LEN))
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use bytes::BytesMut;

    #[test]
    fn round_trip() {
        let frame = encode(b"payload");
        assert_eq!(
            decode(BytesMut::from(frame.as_slice())).unwrap(),
            BytesMut::from(&b"payload"[..])
        );
    }

    #[test]
    fn rejects_legacy_payload() {
        assert!(decode(BytesMut::from(&b"legacy"[..])).is_err());
    }
    #[test]
    fn rejects_invalid_headers() {
        for index in [0, 4, 5, 6] {
            let mut frame = encode(b"payload");
            frame[index] ^= 1;
            assert!(decode(BytesMut::from(frame.as_slice())).is_err());
        }
        assert!(decode(BytesMut::from(&encode(b"payload")[..6])).is_err());
    }
}
