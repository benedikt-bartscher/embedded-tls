// The client offers the RSA schemes with `enable_rsa_signatures` and does not verify the server,
// so this needs no signature feature.
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::Write as _;
use std::net::SocketAddr;
use std::sync::Once;

mod common;
mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    init_log();
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            use tlsserver::*;

            let versions = &[&rustls::version::TLS13];

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let certs = load_certs(&test_dir.join("data").join("rsa-server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("rsa-server-key.pem"));

            let config = rustls::ServerConfig::builder()
                .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
                .with_kx_groups(&rustls::ALL_KX_GROUPS)
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, privkey)
                .unwrap();

            run_with_config(listener, config);
        });
        #[allow(static_mut_refs)]
        unsafe {
            ADDR.replace(addr)
        };
    });
    unsafe { ADDR.unwrap() }
}

#[tokio::test]
async fn test_ping_rsa_server_without_verification() {
    use embedded_tls::*;

    let addr = setup();
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16640];
    let mut write_record_buffer = [0; 16640];

    let config = TlsConfig::new()
        .with_server_name("localhost")
        .enable_rsa_signatures();

    let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    tls.open(TlsContext::new(&config, InsecureNoVerify))
        .await
        .expect("error establishing TLS connection");

    tls.write_all(b"ping").await.expect("error writing data");
    tls.flush().await.expect("error flushing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    assert_eq!(b"ping", &rx_buf[..sz]);

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
