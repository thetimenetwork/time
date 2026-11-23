//! Loopback-only ABCI socket server.
//!
//! CometBFT writes many requests into each connection before it waits for
//! answers; the mempool connection in particular carries bursts of `CheckTx`.
//! This server reads every complete request already received, answers runs of
//! `CheckTx` in parallel and everything else one at a time, and writes the
//! answers in request order with one flush. Request order on a connection is
//! the only ordering ABCI requires, and it is preserved.
//!
//! The endpoint is a trusted local interface, not an authenticated public API.
//! On a loopback TCP port any program on the machine can reach it. On a Unix
//! socket (`Endpoint::Unix`) only the node's own user can.
use prost::Message;
use std::{
    fmt,
    io::{self, BufWriter, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    Request, RequestCheckTx, Response, ResponseCheckTx, request, response,
};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// The largest request frame read. Answers stay within `MAX_FRAME_BYTES`,
/// and so does every request this node expects, with one exception that is
/// not in its hands: during a state sync CometBFT 0.38 hands the application
/// whatever a peer sent as a snapshot chunk, without looking at its size
/// (`statesync/chunks.go`, `chunkQueue.Add`), and a peer's chunk message may
/// be 16,000,000 bytes (`statesync/messages.go`, `chunkMsgSize`, the receive
/// capacity of the chunk channel in `statesync/reactor.go`). The request
/// that carries it adds an index, the sender's node id and field headers.
/// Such a frame must be read and answered (`ApplySnapshotChunk` refuses the
/// chunk and names its sender): closing the connection instead would stop
/// CometBFT, which ends itself when an ABCI connection ends
/// (`proxy/multi_app_conn.go`). Requests of other kinds above
/// `MAX_FRAME_BYTES` are refused by the application as before.
pub const MAX_REQUEST_FRAME_BYTES: usize = 16_000_000 + 64 * 1024;
pub const MAX_CONNECTIONS: usize = 16;
/// Time allowed for the rest of a request once its first byte has arrived.
const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
/// Time allowed for the peer to take the answers it asked for.
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
const READ_CHUNK: usize = 256 * 1024;
/// Requests answered together before the answers are written.
const MAX_BATCH: usize = 2048;

/// Mempool admission for a run of consecutive `CheckTx` requests. Results
/// are returned in request order.
pub trait BatchCheck {
    fn check_batch(&self, requests: Vec<RequestCheckTx>) -> Vec<ResponseCheckTx>;
    /// Called when a connection has delivered its first valid request.
    fn peer_connected(&self) {}
    /// Called by the thread that answered a batch, at the end of the batch,
    /// once all its answers have been written and flushed to the peer.
    fn answers_written(&self) {}
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Outcome of looking for one length-prefixed frame at the front of a buffer.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// More bytes are needed.
    Incomplete,
    /// A frame of `payload` bytes follows a prefix of `prefix` bytes.
    Complete { prefix: usize, payload: usize },
}

/// Parses the unsigned protobuf varint length prefix without allocating.
fn frame_bounds(buffer: &[u8]) -> io::Result<Frame> {
    let mut length = 0u64;
    for index in 0..10 {
        let Some(&byte) = buffer.get(index) else {
            return Ok(Frame::Incomplete);
        };
        if index == 9 && byte > 1 {
            return Err(invalid("ABCI frame length overflow"));
        }
        length |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(invalid("noncanonical ABCI frame length"));
            }
            if length == 0 || length > MAX_REQUEST_FRAME_BYTES as u64 {
                return Err(invalid("ABCI frame length outside allowed range"));
            }
            let (prefix, payload) = (index + 1, length as usize);
            return Ok(if buffer.len() >= prefix + payload {
                Frame::Complete { prefix, payload }
            } else {
                Frame::Incomplete
            });
        }
    }
    Err(invalid("ABCI frame length overflow"))
}

/// Where the ABCI server listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A loopback TCP port.
    Tcp(SocketAddr),
    /// A Unix socket, created with access for the node's own user only.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, String> {
        if let Some(path) = text.strip_prefix("unix:") {
            return unix_endpoint(Path::new(path));
        }
        let addr: SocketAddr = text.parse().map_err(|_| {
            "--listen must be unix:/absolute/path or a literal loopback IP and port".to_string()
        })?;
        if !addr.ip().is_loopback() || addr.port() == 0 {
            return Err("ABCI must listen on a nonzero loopback port".into());
        }
        Ok(Self::Tcp(addr))
    }
}

#[cfg(unix)]
fn unix_endpoint(path: &Path) -> Result<Endpoint, String> {
    if !path.is_absolute() {
        return Err("the ABCI socket needs an absolute path".into());
    }
    Ok(Endpoint::Unix(path.to_path_buf()))
}

#[cfg(not(unix))]
fn unix_endpoint(_path: &Path) -> Result<Endpoint, String> {
    Err("Unix sockets are not available on this platform".into())
}

/// What the server needs from a connection.
trait Wire: Read + Write + Sized + Send + 'static {
    fn duplicate(&self) -> io::Result<Self>;
    fn read_deadline(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn write_deadline(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Wire for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn read_deadline(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn write_deadline(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

#[cfg(unix)]
impl Wire for std::os::unix::net::UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn read_deadline(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn write_deadline(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

/// Buffered reader of ABCI request frames.
struct Requests<S> {
    stream: S,
    buffer: Vec<u8>,
    start: usize,
    /// When the partial frame at the front of the buffer started arriving.
    partial_since: Option<Instant>,
}

impl<S: Wire> Requests<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::with_capacity(READ_CHUNK),
            start: 0,
            partial_since: None,
        }
    }

    /// A complete request already in the buffer, if any.
    fn buffered(&mut self) -> io::Result<Option<Request>> {
        match frame_bounds(&self.buffer[self.start..])? {
            Frame::Incomplete => Ok(None),
            Frame::Complete { prefix, payload } => {
                let from = self.start + prefix;
                let request = Request::decode(&self.buffer[from..from + payload])
                    .map_err(|_| invalid("malformed ABCI protobuf request"))?;
                self.start = from + payload;
                if self.start == self.buffer.len() {
                    self.buffer.clear();
                    self.start = 0;
                    // A frame as large as a peer's snapshot chunk is rare:
                    // the room it took is not kept for the connection's life.
                    if self.buffer.capacity() > MAX_FRAME_BYTES {
                        self.buffer.shrink_to(READ_CHUNK);
                    }
                }
                self.partial_since = None;
                Ok(Some(request))
            }
        }
    }

    /// The next request, waiting for it if needed. `None` on a clean close
    /// between requests.
    fn next(&mut self) -> io::Result<Option<Request>> {
        loop {
            if let Some(request) = self.buffered()? {
                return Ok(Some(request));
            }
            // Drop consumed bytes before reading more.
            if self.start > 0 {
                self.buffer.drain(..self.start);
                self.start = 0;
            }
            let pending = !self.buffer.is_empty();
            let timeout = if pending {
                let since = *self.partial_since.get_or_insert_with(Instant::now);
                let left = FRAME_TIMEOUT.checked_sub(since.elapsed()).filter(|d| !d.is_zero());
                Some(left.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "ABCI frame deadline exceeded")
                })?)
            } else {
                // CometBFT keeps connections idle for long periods.
                None
            };
            self.stream.read_deadline(timeout)?;
            let filled = self.buffer.len();
            self.buffer.resize(filled + READ_CHUNK, 0);
            let read = loop {
                match self.stream.read(&mut self.buffer[filled..]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    other => break other,
                }
            };
            let count = match read {
                Ok(count) => count,
                Err(error) => {
                    self.buffer.truncate(filled);
                    return Err(match error.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                            io::Error::new(io::ErrorKind::TimedOut, "ABCI frame deadline exceeded")
                        }
                        _ => error,
                    });
                }
            };
            self.buffer.truncate(filled + count);
            if count == 0 {
                return if pending {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed inside an ABCI frame",
                    ))
                } else {
                    Ok(None)
                };
            }
        }
    }
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
    writer.write_all(&frame)
}

fn dispatch(app: &impl Application, value: request::Value) -> response::Value {
    match value {
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
    }
}

/// Answers a batch in request order, writing every answer as soon as it
/// exists: however many requests arrive together, at most one answer (a proof
/// query can return megabytes) is held in memory. A run of consecutive
/// `CheckTx` requests is handed to the application as one batch, so it can
/// verify signatures on all cores and still admit the transactions in order.
fn answer<A: Application + BatchCheck>(
    app: &A,
    batch: Vec<Request>,
    writer: &mut impl Write,
) -> io::Result<()> {
    fn checks<A: BatchCheck>(
        app: &A,
        pending: &mut Vec<RequestCheckTx>,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let expected = pending.len();
        let results = app.check_batch(std::mem::take(pending));
        // One answer per request is part of the transport's ordering promise.
        assert_eq!(results.len(), expected, "CheckTx batch answer count");
        for result in results {
            write_frame(
                &Response {
                    value: Some(response::Value::CheckTx(result)),
                },
                writer,
            )?;
        }
        Ok(())
    }
    let mut pending = Vec::new();
    for request in batch {
        match request
            .value
            .ok_or_else(|| invalid("ABCI request has no operation"))?
        {
            request::Value::CheckTx(check) => pending.push(check),
            other => {
                checks(app, &mut pending, writer)?;
                // The answers to a Commit and to a Flush leave at once. An
                // application that stops after a block answers no consensus
                // request that follows in the batch, and the consensus engine
                // must have both: its Commit call waits for the answer to the
                // Flush it sends behind the Commit.
                let leaves = matches!(other, request::Value::Commit(_) | request::Value::Flush(_));
                write_frame(
                    &Response {
                        value: Some(dispatch(app, other)),
                    },
                    writer,
                )?;
                if leaves {
                    writer.flush()?;
                }
            }
        }
    }
    checks(app, &mut pending, writer)
}

/// Shared connection accounting for `serve`.
struct Tracker {
    open: AtomicUsize,
    /// Connections that have sent at least one valid request.
    established: AtomicUsize,
    seen_peer: AtomicBool,
}

fn connection<A: Application + BatchCheck, S: Wire>(
    stream: S,
    app: &A,
    tracker: &Tracker,
) -> io::Result<()> {
    stream.write_deadline(Some(WRITE_TIMEOUT))?;
    let mut writer = BufWriter::with_capacity(READ_CHUNK, stream.duplicate()?);
    let mut requests = Requests::new(stream);
    let mut established = false;
    let result = (|| -> io::Result<()> {
        loop {
            let Some(first) = requests.next()? else {
                return Ok(());
            };
            if !established {
                established = true;
                tracker.established.fetch_add(1, Ordering::AcqRel);
                tracker.seen_peer.store(true, Ordering::Release);
                app.peer_connected();
            }
            let mut batch = vec![first];
            while batch.len() < MAX_BATCH {
                match requests.buffered()? {
                    Some(request) => batch.push(request),
                    None => break,
                }
            }
            answer(app, batch, &mut writer)?;
            writer.flush()?;
            app.answers_written();
        }
    })();
    if established {
        tracker.established.fetch_sub(1, Ordering::AcqRel);
    }
    result
}

/// Serves ABCI on a loopback address until the process exits.
///
/// `on_peer_gone` is called each time the last connection that carried ABCI
/// requests closes, which is how the node learns that its consensus engine
/// has stopped. A bare TCP connect and close (a port probe) does not count.
///
/// Application invariant panics are not swallowed: the binary's global panic
/// hook must stop the process rather than continue from unsafe state.
pub fn serve<A>(
    addr: SocketAddr,
    app: A,
    on_peer_gone: impl Fn() + Send + Sync + 'static,
) -> io::Result<()>
where
    A: Application + BatchCheck + Sync + Clone + Send + 'static,
{
    serve_on(Endpoint::Tcp(addr), app, on_peer_gone)
}

/// As `serve`, on a TCP port or a Unix socket.
pub fn serve_on<A>(
    endpoint: Endpoint,
    app: A,
    on_peer_gone: impl Fn() + Send + Sync + 'static,
) -> io::Result<()>
where
    A: Application + BatchCheck + Sync + Clone + Send + 'static,
{
    match endpoint {
        Endpoint::Tcp(addr) => {
            if !addr.ip().is_loopback() || addr.port() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ABCI transport requires a nonzero loopback address",
                ));
            }
            let listener = TcpListener::bind(addr)?;
            accept_all(
                listener.incoming(),
                |stream: &TcpStream| {
                    stream.peer_addr().is_ok_and(|peer| peer.ip().is_loopback())
                        && stream.set_nodelay(true).is_ok()
                },
                app,
                on_peer_gone,
            )
        }
        #[cfg(unix)]
        Endpoint::Unix(path) => {
            let listener = bind_private(&path)?;
            accept_all(
                listener.incoming(),
                |_: &std::os::unix::net::UnixStream| true,
                app,
                on_peer_gone,
            )
        }
    }
}

/// Binds a Unix socket that only this process's user can open. A socket left
/// by an earlier run is replaced; anything else under that name is left alone.
#[cfg(unix)]
fn bind_private(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the ABCI socket path exists and is not a socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // The socket is created without access for group and others from the
    // first moment, so there is no window in which another user could connect.
    // SAFETY: `umask` only replaces this process's file mode creation mask.
    let previous = unsafe { libc::umask(0o177) };
    let bound = std::os::unix::net::UnixListener::bind(path);
    // SAFETY: as above; restores the mask the process had.
    unsafe { libc::umask(previous) };
    let listener = bound?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn accept_all<A, S>(
    incoming: impl Iterator<Item = io::Result<S>>,
    admit: impl Fn(&S) -> bool,
    app: A,
    on_peer_gone: impl Fn() + Send + Sync + 'static,
) -> io::Result<()>
where
    A: Application + BatchCheck + Sync + Clone + Send + 'static,
    S: Wire,
{
    let tracker = Arc::new(Tracker {
        open: AtomicUsize::new(0),
        established: AtomicUsize::new(0),
        seen_peer: AtomicBool::new(false),
    });
    let on_peer_gone = Arc::new(on_peer_gone);
    for stream in incoming {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("ABCI accept failed: {error}");
                continue;
            }
        };
        if !admit(&stream) {
            continue;
        }
        if tracker.open.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            tracker.open.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let (app, shared, on_peer_gone) = (app.clone(), tracker.clone(), on_peer_gone.clone());
        let spawned = thread::Builder::new()
            .name("abci-connection".into())
            .spawn(move || {
                if let Err(error) = connection(stream, &app, &shared) {
                    eprintln!("ABCI connection closed: {error}");
                }
                shared.open.fetch_sub(1, Ordering::AcqRel);
                if shared.seen_peer.load(Ordering::Acquire)
                    && shared.established.load(Ordering::Acquire) == 0
                {
                    on_peer_gone();
                }
            });
        if let Err(error) = spawned {
            // The connection never ran: give its slot back.
            tracker.open.fetch_sub(1, Ordering::AcqRel);
            eprintln!("ABCI connection thread failed to start: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint_proto::v0_38::abci::{RequestEcho, RequestFlush};

    fn encode(request: &Request) -> Vec<u8> {
        let mut frame = Vec::new();
        let mut left = request.encoded_len() as u64;
        while left >= 0x80 {
            frame.push((left as u8 & 0x7f) | 0x80);
            left >>= 7;
        }
        frame.push(left as u8);
        request.encode(&mut frame).unwrap();
        frame
    }

    #[test]
    fn frame_prefix_rules() {
        assert_eq!(frame_bounds(&[]).unwrap(), Frame::Incomplete);
        assert_eq!(frame_bounds(&[5, 1, 2]).unwrap(), Frame::Incomplete);
        assert_eq!(
            frame_bounds(&[2, 9, 9, 7]).unwrap(),
            Frame::Complete {
                prefix: 1,
                payload: 2
            }
        );
        // Zero length, noncanonical padding, and oversized frames are refused
        // before any payload is buffered.
        assert!(frame_bounds(&[0]).is_err());
        assert!(frame_bounds(&[0x80, 0x00]).is_err());
        let too_large = (MAX_REQUEST_FRAME_BYTES as u64 + 1).to_le_bytes();
        let mut prefix = Vec::new();
        let mut left = u64::from_le_bytes(too_large);
        while left >= 0x80 {
            prefix.push((left as u8 & 0x7f) | 0x80);
            left >>= 7;
        }
        prefix.push(left as u8);
        assert!(frame_bounds(&prefix).is_err());
        assert!(frame_bounds(&[0xff; 10]).is_err());
    }

    #[derive(Clone)]
    struct Probe(Arc<AtomicUsize>);
    impl Application for Probe {}
    impl BatchCheck for Probe {
        fn peer_connected(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn check_batch(&self, requests: Vec<RequestCheckTx>) -> Vec<ResponseCheckTx> {
            // Echo each transaction back so the test can check the order.
            requests
                .into_iter()
                .map(|request| ResponseCheckTx {
                    data: request.tx,
                    ..Default::default()
                })
                .collect()
        }
    }

    #[test]
    fn batched_answers_keep_request_order() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let connected = Arc::new(AtomicUsize::new(0));
        let probe = Probe(connected.clone());
        thread::spawn(move || serve(addr, probe, || {}).unwrap());
        let mut client = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let mut bytes = encode(&Request {
            value: Some(request::Value::Echo(RequestEcho {
                message: "hello".into(),
            })),
        });
        for index in 0u32..500 {
            bytes.extend(encode(&Request {
                value: Some(request::Value::CheckTx(RequestCheckTx {
                    tx: index.to_be_bytes().to_vec().into(),
                    r#type: 0,
                })),
            }));
            if index % 97 == 0 {
                bytes.extend(encode(&Request {
                    value: Some(request::Value::Flush(RequestFlush {})),
                }));
            }
        }
        // Send in awkward pieces so frames straddle reads.
        for piece in bytes.chunks(777) {
            client.write_all(piece).unwrap();
        }
        client.flush().unwrap();
        let mut reader = Requests::new(client.try_clone().unwrap());
        assert!(matches!(
            read_response(&mut reader).value,
            Some(response::Value::Echo(_))
        ));
        for index in 0u32..500 {
            match read_response(&mut reader).value {
                Some(response::Value::CheckTx(check)) => {
                    assert_eq!(check.data.as_ref(), &index.to_be_bytes()[..])
                }
                other => panic!("expected CheckTx answer {index}, got {other:?}"),
            }
            if index % 97 == 0 {
                assert!(matches!(
                    read_response(&mut reader).value,
                    Some(response::Value::Flush(_))
                ));
            }
        }
        // The application was told once that a peer connected.
        assert_eq!(connected.load(Ordering::SeqCst), 1);
    }

    /// Reads one answer from the server.
    fn read_response<S: Wire>(reader: &mut Requests<S>) -> Response {
        loop {
            if let Frame::Complete { prefix, payload } =
                frame_bounds(&reader.buffer[reader.start..]).unwrap()
            {
                let from = reader.start + prefix;
                let response = Response::decode(&reader.buffer[from..from + payload]).unwrap();
                reader.start = from + payload;
                return response;
            }
            let mut chunk = [0u8; 4096];
            let count = reader.stream.read(&mut chunk).unwrap();
            assert!(count > 0, "server closed the connection");
            reader.buffer.extend_from_slice(&chunk[..count]);
        }
    }

    #[test]
    fn endpoints_are_parsed_strictly() {
        assert_eq!(
            "127.0.0.1:26658".parse::<Endpoint>().unwrap().to_string(),
            "127.0.0.1:26658"
        );
        for bad in ["0.0.0.0:26658", "example.com:26658", "127.0.0.1:0", "unix:relative/path", "unix:", ""] {
            assert!(bad.parse::<Endpoint>().is_err(), "{bad}");
        }
        #[cfg(unix)]
        assert_eq!(
            "unix:/run/time/abci.sock".parse::<Endpoint>().unwrap(),
            Endpoint::Unix(std::path::PathBuf::from("/run/time/abci.sock"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_socket_is_private_to_the_node_user_and_serves_in_order() {
        use std::os::unix::{fs::PermissionsExt, net::UnixStream};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("abci.sock");
        // A file that is not a socket is refused, not replaced.
        std::fs::write(&path, b"keep").unwrap();
        let probe = Probe(Arc::new(AtomicUsize::new(0)));
        assert!(serve_on(Endpoint::Unix(path.clone()), probe.clone(), || {}).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        let served = path.clone();
        thread::spawn(move || serve_on(Endpoint::Unix(served), probe, || {}).unwrap());
        let mut client = loop {
            match UnixStream::connect(&path) {
                Ok(stream) => break stream,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        // Owner only: no access for the group or for others.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "socket mode {mode:o}");
        let mut bytes = Vec::new();
        for index in 0u32..50 {
            bytes.extend(encode(&Request {
                value: Some(request::Value::CheckTx(RequestCheckTx {
                    tx: index.to_be_bytes().to_vec().into(),
                    r#type: 0,
                })),
            }));
        }
        bytes.extend(encode(&Request {
            value: Some(request::Value::Flush(RequestFlush {})),
        }));
        client.write_all(&bytes).unwrap();
        client.flush().unwrap();
        let mut reader = Requests::new(client.try_clone().unwrap());
        for index in 0u32..50 {
            match read_response(&mut reader).value {
                Some(response::Value::CheckTx(check)) => {
                    assert_eq!(check.data.as_ref(), &index.to_be_bytes()[..])
                }
                other => panic!("expected CheckTx answer {index}, got {other:?}"),
            }
        }
        assert!(matches!(
            read_response(&mut reader).value,
            Some(response::Value::Flush(_))
        ));
    }
}
