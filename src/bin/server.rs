use native_tls::{Certificate, Identity, TlsAcceptor};

use std::fmt::Debug;
use std::fs::File;
use std::io::Read;

use websocket::message::{Message, OwnedMessage};
use websocket::r#async::Server;
use websocket::server::InvalidConnection;

use futures::{future, Future, Sink, Stream};
use tokio::runtime::TaskExecutor;

use openssl::x509::X509;

fn main() {
    let mut runtime = tokio::runtime::Builder::new().build().unwrap();
    let executor = runtime.executor();
    let mut file = File::open("pikachu.org.p12").unwrap();
    let mut identity = vec![];
    file.read_to_end(&mut identity).unwrap();
    let identity = Identity::from_pkcs12(&identity, "changeit").unwrap();
    let acceptor = TlsAcceptor::new(identity).unwrap();
    // bind to the server
    let server = Server::bind_secure(
        "127.0.0.1:2794",
        acceptor,
        &tokio::reactor::Handle::default(),
    )
    .unwrap();

    // time to build the server's future
    // this will be a struct containing everything the server is going to do

    // a stream of incoming connections
    let f = server
        .incoming()
        .then(future::ok) // wrap good and bad events into future::ok
        .filter(|event| {
            match event {
                Ok(_) => true, // a good connection
                Err(InvalidConnection { ref error, .. }) => {
                    println!("Bad client: {}", error);
                    false // we want to save the stream if a client cannot make a valid handshake
                }
            }
        })
        .and_then(|event| event) // unwrap good connections
        .map_err(|_| ()) // and silently ignore errors (in `.filter`)
        .for_each(move |(upgrade, addr)| {
            println!("Got a connection from: {}", addr);
            println!("Stream: {:#?}", upgrade.stream);
            println!(
                "Peer certificate: {}",
                display_cert(upgrade.stream.get_ref().peer_certificate().unwrap())
            );
            // check if it has the protocol we want
            if !upgrade.protocols().iter().any(|s| s == "rust-websocket") {
                // reject it if it doesn't
                spawn_future(upgrade.reject(), "Upgrade Rejection", &executor);
                return Ok(());
            }

            // accept the request to be a ws connection if it does
            let f = upgrade
                .use_protocol("rust-websocket")
                .accept()
                // send a greeting!
                .and_then(|(s, _)| s.send(Message::text("Hello World!").into()))
                // simple echo server impl
                .and_then(|s| {
                    let (sink, stream) = s.split();
                    stream
                        .take_while(|m| Ok(!m.is_close()))
                        .filter_map(|m| {
                            println!("Message from Client: {:?}", m);
                            match m {
                                OwnedMessage::Ping(p) => Some(OwnedMessage::Pong(p)),
                                OwnedMessage::Pong(_) => None,
                                _ => Some(m),
                            }
                        })
                        .forward(sink)
                        .and_then(|(_, sink)| sink.send(OwnedMessage::Close(None)))
                });

            spawn_future(f, "Client Status", &executor);
            Ok(())
        });

    runtime.block_on(f).unwrap();
}

fn spawn_future<F, I, E>(f: F, desc: &'static str, executor: &TaskExecutor)
where
    F: Future<Item = I, Error = E> + 'static + Send,
    E: Debug,
{
    executor.spawn(
        f.map_err(move |e| println!("{}: '{:?}'", desc, e))
            .map(move |_| println!("{}: Finished.", desc)),
    );
}

fn display_cert(cert: Option<Certificate>) -> String {
    let c = match cert {
        None => return format!("Certificate(None)"),
        Some(c) => c,
    };

    let x = X509::from_der(&c.to_der().unwrap()).unwrap();
    let mut subj: Vec<String> = vec![];
    for n in x.subject_name().entries() {
        let s = n.data().as_utf8().unwrap();
        subj.push(format!("{}", s));
    }
    SliceConcatExt::join(&subj[..], &",")
}