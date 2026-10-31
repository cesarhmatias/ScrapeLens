//! O guarda do `Client` não deixa `fake_server` órfão, nem em panic.

mod common;

use common::client::{fake_server, Client, Elicit};

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn client_drop_reaps_the_server_even_when_the_test_panics() {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let pid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = pid.clone();
    let result = std::panic::catch_unwind(move || {
        let mut client = Client::start(
            &fake_server(),
            &["--sessions-dir", sessions.to_str().unwrap()],
            Elicit::Accept,
        );
        client.handshake();
        seen.store(client.child.id(), std::sync::atomic::Ordering::SeqCst);
        panic!("falha simulada com o servidor vivo");
    });
    assert!(result.is_err());
    let pid = pid.load(std::sync::atomic::Ordering::SeqCst);
    assert_ne!(pid, 0);
    assert!(!alive(pid), "o servidor {pid} sobreviveu ao panic do teste");
}
