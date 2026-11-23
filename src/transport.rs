//! Bounded, loopback-only ABCI socket transport using the official protobuf
//! messages and Application trait. This is not a consensus implementation.
//!
//! The endpoint remains a trusted local interface, not an authenticated public
//! API. Idle connections use capped slots and can starve other local clients;
//! a multi-user host needs additional isolation/authentication before production.

use prost::Message;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{Request, Response, request, response};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CONNECTIONS: usize = 16;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone)]
struct Slots {
    active: Arc<AtomicUsize>,
    limit: usize,
}

struct Slot {
    active: Arc<AtomicUsize>,
}

impl Slots {
    fn new(limit: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }
    fn acquire(&self) -> Option<Slot> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Slot {
                        active: self.active.clone(),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "ABCI frame deadline exceeded"))
}

struct DeadlineRead<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        normalize_timeout(self.stream.read(bytes))
    }
}

struct DeadlineWrite<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Write for DeadlineWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        normalize_timeout(self.stream.write(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        normalize_timeout(self.stream.flush())
    }
}

fn normalize_timeout<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            io::Error::new(io::ErrorKind::TimedOut, "ABCI frame deadline exceeded")
        } else {
            error
        }
    })
}

/// Parse the unsigned protobuf varint before allocating any payload buffer.
/// The first byte has already arrived, so any incomplete prefix is a malformed
/// frame rather than a clean idle/EOF boundary.
fn read_frame(first: u8, reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = 0u64;
    let mut byte = first;
    for index in 0..10 {
        if index > 0 {
            reader.read_exact(std::slice::from_mut(&mut byte))?;
        }
        if index == 9 && byte > 1 {
            return Err(invalid("ABCI frame length overflow"));
        }
        length |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(invalid("noncanonical ABCI frame length"));
            }
            if length == 0 || length > MAX_FRAME_BYTES as u64 {
                return Err(invalid("ABCI frame length outside allowed range"));
            }
            let mut payload = vec![0; length as usize];
            reader.read_exact(&mut payload)?;
            return Ok(payload);
        }
    }
    Err(invalid("ABCI frame length overflow"))
}

fn write_frame(response: &Response, writer: &mut impl Write) -> io::Result<()> {
    let length = response.encoded_len();
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid("ABCI response exceeds frame limit"));
    }
    let mut frame = Vec::with_capacity(length + 10);
    let mut left = length as u64;
    while left >= 0x80 {
        frame.push((left as u8 & 0x7f) | 0x80);
        left >>= 7;
    }
    frame.push(left as u8);
    response
        .encode(&mut frame)
        .map_err(|_| invalid("ABCI response encoding failed"))?;
    writer.write_all(&frame)?;
    writer.flush()
}

fn dispatch(app: &impl Application, request: Request) -> io::Result<Response> {
    // Avoid upstream RequestDispatcher's unchecked unwrap and raw-request debug
    // logging. A malformed frame is a connection error, not an app invariant.
    let value = match request
        .value
        .ok_or_else(|| invalid("ABCI request has no operation"))?
    {
        request::Value::Echo(req) => response::Value::Echo(app.echo(req)),
        request::Value::Flush(_) => response::Value::Flush(app.flush()),
        request::Value::Info(req) => response::Value::Info(app.info(req)),
        request::Value::InitChain(req) => response::Value::InitChain(app.init_chain(req)),
        request::Value::Query(req) => response::Value::Query(app.query(req)),
        request::Value::CheckTx(req) => response::Value::CheckTx(app.check_tx(req)),
        request::Value::Commit(_) => response::Value::Commit(app.commit()),
        request::Value::ListSnapshots(_) => response::Value::ListSnapshots(app.list_snapshots()),
        request::Value::OfferSnapshot(req) => {
            response::Value::OfferSnapshot(app.offer_snapshot(req))
        }
        request::Value::LoadSnapshotChunk(req) => {
            response::Value::LoadSnapshotChunk(app.load_snapshot_chunk(req))
        }
        request::Value::ApplySnapshotChunk(req) => {
            response::Value::ApplySnapshotChunk(app.apply_snapshot_chunk(req))
        }
        request::Value::PrepareProposal(req) => {
            response::Value::PrepareProposal(app.prepare_proposal(req))
        }
        request::Value::ProcessProposal(req) => {
            response::Value::ProcessProposal(app.process_proposal(req))
        }
        request::Value::ExtendVote(req) => response::Value::ExtendVote(app.extend_vote(req)),
        request::Value::VerifyVoteExtension(req) => {
            response::Value::VerifyVoteExtension(app.verify_vote_extension(req))
        }
        request::Value::FinalizeBlock(req) => {
            response::Value::FinalizeBlock(app.finalize_block(req))
        }
    };
    Ok(Response { value: Some(value) })
}

fn connection(mut stream: TcpStream, app: impl Application, timeout: Duration) -> io::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        // CometBFT keeps query/mempool connections idle for long periods. A
        // deadline starts only once a new frame's first byte has arrived.
        stream.set_read_timeout(None)?;
        let mut first = [0];
        let count = loop {
            match stream.read(&mut first) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if count == 0 {
            return Ok(());
        }
        let payload = read_frame(
            first[0],
            &mut DeadlineRead {
                stream: &mut stream,
                deadline: Instant::now() + timeout,
            },
        )?;
        let request = Request::decode(payload.as_slice())
            .map_err(|_| invalid("malformed ABCI protobuf request"))?;
        let response = dispatch(&app, request)?;
        write_frame(
            &response,
            &mut DeadlineWrite {
                stream: &mut stream,
                deadline: Instant::now() + timeout,
            },
        )?;
    }
}

/// Serve official ABCI protobuf frames on a trusted, bounded local interface.
/// App invariant panics are not swallowed: the binary's global panic hook must
/// stop all connections rather than continuing from potentially unsafe state.
pub fn serve(addr: SocketAddr, app: impl Application) -> io::Result<()> {
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ABCI transport requires a nonzero loopback address",
        ));
    }
    let listener = TcpListener::bind(addr)?;
    let slots = Slots::new(MAX_CONNECTIONS);
    loop {
        let (stream, _) = match listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        let Some(slot) = slots.acquire() else {
            drop(stream);
            continue;
        };
        let app = app.clone();
        thread::Builder::new()
            .name("abci-local".into())
            .spawn(move || {
                let _slot = slot;
                // Framing/deadline failures drop only this connection. Never log
                // request bodies, which can contain sensitive application metadata.
                let _ = connection(stream, app, FRAME_TIMEOUT);
            })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, net::Shutdown};
    use tendermint_proto::v0_38::abci::{RequestEcho, RequestFlush, ResponseEcho};

    #[derive(Clone)]
    struct Echo;
    impl Application for Echo {}

    fn encoded(request: &Request) -> Vec<u8> {
        request.encode_length_delimited_to_vec()
    }

    fn read_response(stream: &mut TcpStream) -> Response {
        let mut first = [0];
        stream.read_exact(&mut first).unwrap();
        Response::decode(read_frame(first[0], stream).unwrap().as_slice()).unwrap()
    }

    fn one_connection(timeout: Duration) -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            connection(stream, Echo, timeout)
        });
        (addr, handle)
    }

    #[test]
    fn oversized_prefix_rejects_before_reading_or_allocating_payload() {
        // unsigned varint 10MiB, then unrelated payload bytes
        let mut input = Cursor::new(vec![0x80, 0x80, 0x05, 7, 8, 9]);
        assert_eq!(
            read_frame(0x80, &mut input).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 3, "must stop after advertised length");
    }

    #[test]
    fn malformed_prefix_overflow_empty_and_truncation_reject() {
        for bytes in [
            vec![0],
            vec![0x81, 0],
            vec![0x80; 11],
            vec![0xff; 10],
            vec![0x80],
        ] {
            let mut input = Cursor::new(bytes[1..].to_vec());
            assert!(read_frame(bytes[0], &mut input).is_err());
        }
        assert_eq!(
            read_frame(3, &mut Cursor::new(vec![1])).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(dispatch(&Echo, Request::default()).is_err());
        let unknown_only = Request::decode([0xa8, 0x06, 0x01].as_slice()).unwrap();
        assert!(dispatch(&Echo, unknown_only).is_err());
    }

    #[test]
    fn connection_slots_are_capped_and_released() {
        let slots = Slots::new(MAX_CONNECTIONS);
        let mut guards = (0..MAX_CONNECTIONS)
            .map(|_| slots.acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(slots.acquire().is_none());
        guards.pop();
        let next = slots.acquire().unwrap();
        assert!(slots.acquire().is_none());
        drop(guards);
        drop(next);
        assert_eq!(slots.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn echo_and_flush_round_trip_on_one_connection() {
        let (addr, server) = one_connection(Duration::from_secs(2));
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = Request {
            value: Some(request::Value::Echo(RequestEcho {
                message: "hello".into(),
            })),
        };
        stream.write_all(&encoded(&request)).unwrap();
        assert_eq!(
            read_response(&mut stream).value,
            Some(response::Value::Echo(ResponseEcho {
                message: "hello".into()
            }))
        );
        stream
            .write_all(&encoded(&Request {
                value: Some(request::Value::Flush(RequestFlush {})),
            }))
            .unwrap();
        assert!(matches!(
            read_response(&mut stream).value,
            Some(response::Value::Flush(_))
        ));
        stream.shutdown(Shutdown::Both).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn idle_connection_is_not_mistaken_for_partial_frame_timeout() {
        let (addr, server) = one_connection(Duration::from_millis(200));
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        thread::sleep(Duration::from_millis(350));
        stream
            .write_all(&encoded(&Request {
                value: Some(request::Value::Flush(RequestFlush {})),
            }))
            .unwrap();
        assert!(matches!(
            read_response(&mut stream).value,
            Some(response::Value::Flush(_))
        ));
        stream.shutdown(Shutdown::Both).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn partial_frame_has_absolute_deadline_despite_trickled_bytes() {
        let (addr, server) = one_connection(Duration::from_millis(180));
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(&[5]).unwrap();
        for _ in 0..5 {
            thread::sleep(Duration::from_millis(70));
            if stream.write_all(&[0]).is_err() {
                break;
            }
        }
        assert_eq!(
            server.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn malformed_connection_does_not_dispatch_or_panic() {
        let (addr, server) = one_connection(Duration::from_secs(2));
        let mut stream = TcpStream::connect(addr).unwrap();
        // Nonempty protobuf carrying only an unknown field has no operation.
        stream.write_all(&[3, 0xa8, 0x06, 0x01]).unwrap();
        assert_eq!(
            server.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn response_size_and_expired_write_deadline_reject() {
        let response = Response {
            value: Some(response::Value::Echo(ResponseEcho {
                message: "x".repeat(MAX_FRAME_BYTES),
            })),
        };
        let mut output = Vec::new();
        assert!(write_frame(&response, &mut output).is_err());
        assert!(output.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut writer = DeadlineWrite {
            stream: &mut stream,
            deadline: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            writer.write(b"x").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn public_or_ephemeral_listener_is_rejected() {
        assert_eq!(
            serve("0.0.0.0:26658".parse().unwrap(), Echo)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            serve("127.0.0.1:0".parse().unwrap(), Echo)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
