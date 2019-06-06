use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;
use native_tls::{Certificate, Identity, TlsConnector};
use std::fs::File;
use std::io::stdin;
use std::io::Read;
use std::thread;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};

const CONNECTION: &'static str = "wss://127.0.0.1:2794";

fn main() {
    println!("Connecting to {}", CONNECTION);
    let mut runtime = tokio::runtime::current_thread::Builder::new()
        .build()
        .unwrap();

    // standard in isn't supported in mio yet, so we use a thread
    // see https://github.com/carllerche/mio/issues/321
    let (usr_msg, stdin_ch) = mpsc::channel(0);
    thread::spawn(|| {
        let mut input = String::new();
        let mut stdin_sink = usr_msg.wait();
        loop {
            input.clear();
            stdin().read_line(&mut input).unwrap();
            let trimmed = input.trim();

            let (close, msg) = match trimmed {
                "/close" => (true, OwnedMessage::Close(None)),
                "/ping" => (false, OwnedMessage::Ping(b"PING".to_vec())),
                _ => (false, OwnedMessage::Text(trimmed.to_string())),
            };

            stdin_sink
                .send(msg)
                .expect("Sending message across stdin channel.");

            if close {
                break;
            }
        }
    });

    let mut file = File::open("client.p12").unwrap();
    let mut ca_file = File::open("rootCA.pem").unwrap();
    let mut ca_cert_pem = vec![];
    ca_file.read_to_end(&mut ca_cert_pem).unwrap();
    let root_ca = Certificate::from_pem(&ca_cert_pem).unwrap();
    let mut identity = vec![];
    file.read_to_end(&mut identity).unwrap();
    let identity = Identity::from_pkcs12(&identity, "changeit").unwrap();

    let connector = TlsConnector::builder()
        .identity(identity)
        .add_root_certificate(root_ca)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let runner = ClientBuilder::new(CONNECTION)
        .unwrap()
        .add_protocol("rust-websocket")
        .async_connect_secure(Some(connector))
        .and_then(|(duplex, _)| {
            let (sink, stream) = duplex.split();
            stream
                .filter_map(|message| {
                    println!("Received Message: {:?}", message);
                    match message {
                        OwnedMessage::Close(e) => Some(OwnedMessage::Close(e)),
                        OwnedMessage::Ping(d) => Some(OwnedMessage::Pong(d)),
                        _ => None,
                    }
                })
                .select(stdin_ch.map_err(|_| WebSocketError::NoDataAvailable))
                .forward(sink)
        });
    runtime.block_on(runner).unwrap();
}
