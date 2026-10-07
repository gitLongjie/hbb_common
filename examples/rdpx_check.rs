use hbb_common::{
    bail,
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    udp::FramedSocket,
    websocket::WsFramedStream,
    ResultType,
};
use std::net::SocketAddr;

async fn receive(stream: &mut FramedStream) -> ResultType<RendezvousMessage> {
    let bytes = stream
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("TCP timeout"))??;
    Ok(RendezvousMessage::parse_from_bytes(&bytes)?)
}

async fn secure(addr: SocketAddr, pk: &sign::PublicKey) -> ResultType<FramedStream> {
    let mut stream = FramedStream::new(addr, None, 3000).await?;
    let message = receive(&mut stream).await?;
    let exchange = message.key_exchange();
    if exchange.keys.len() != 1 {
        bail!("Missing server key exchange");
    }
    let signed = sign::verify(&exchange.keys[0], pk)
        .map_err(|_| hbb_common::anyhow::anyhow!("Invalid server signature"))?;
    let remote = box_::PublicKey::from_slice(&signed)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Invalid X25519 key"))?;
    let (local, sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let sealed = box_::seal(&key.0, &box_::Nonce([0; box_::NONCEBYTES]), &remote, &sk);
    let mut message = RendezvousMessage::new();
    message.set_key_exchange(KeyExchange {
        keys: vec![Bytes::copy_from_slice(&local.0), sealed.into()],
        ..Default::default()
    });
    stream.send(&message).await?;
    stream.set_key(key);
    Ok(stream)
}

async fn udp_receive(socket: &mut FramedSocket) -> ResultType<RendezvousMessage> {
    let (bytes, _) = socket
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("UDP timeout"))??;
    Ok(RendezvousMessage::parse_from_bytes(&bytes)?)
}

#[tokio::main]
async fn main() -> ResultType<()> {
    sodiumoxide::init().map_err(|_| hbb_common::anyhow::anyhow!("Sodium init failed"))?;
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("Usage: rdpx_check HBBS_ADDR HBBR_ADDR PUBLIC_KEY_FILE");
    }
    let server: SocketAddr = args[1].parse()?;
    let relay: SocketAddr = args[2].parse()?;
    use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
    let key = std::fs::read_to_string(&args[3])?;
    let key_bytes = STANDARD.decode(key.trim())?;
    let pk = sign::PublicKey::from_slice(&key_bytes)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Invalid public key"))?;
    let mut udp = FramedSocket::new("127.0.0.1:0").await?;
    // A rejected legacy packet must not stop the rendezvous UDP listener.
    udp.send_raw(b"legacy", server).await?;
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: "777777".into(),
        uuid: vec![7; 16].into(),
        pk: vec![7; 32].into(),
        ..Default::default()
    });
    udp.send(&message, server).await?;
    assert_eq!(
        udp_receive(&mut udp)
            .await?
            .register_pk_response()
            .result
            .enum_value(),
        Ok(register_pk_response::Result::OK)
    );
    message.set_test_nat_request(TestNatRequest::new());
    udp.send(&message, server).await?;
    assert!(udp_receive(&mut udp).await?.test_nat_response().port > 0);
    println!("PASS UDP registration, NAT and legacy rejection");

    let mut controller = secure(server, &pk).await?;
    #[cfg(feature = "webrtc")]
    let mut offerer = hbb_common::webrtc::WebRTCStream::new("", false, 20000).await?;
    #[cfg(feature = "webrtc")]
    let offer = offerer.local_endpoint().to_owned();
    #[cfg(not(feature = "webrtc"))]
    let offer = "webrtc://test-offer".to_owned();
    message.set_punch_hole_request(PunchHoleRequest {
        id: "777777".into(),
        licence_key: key.trim().into(),
        version: "1.5.0".into(),
        webrtc_sdp_offer: offer.clone(),
        ..Default::default()
    });
    controller.send(&message).await?;
    let request = udp_receive(&mut udp).await?;
    let punch = request.punch_hole();
    assert_eq!(punch.webrtc_sdp_offer, offer);
    let route = punch.socket_addr.clone();
    #[cfg(feature = "webrtc")]
    let mut answerer = hbb_common::webrtc::WebRTCStream::new(&offer, false, 20000).await?;
    #[cfg(feature = "webrtc")]
    let answer = answerer.local_endpoint().to_owned();
    #[cfg(not(feature = "webrtc"))]
    let answer = "webrtc://test-answer".to_owned();
    let mut controlled = secure(server, &pk).await?;
    message.set_punch_hole_sent(PunchHoleSent {
        id: "777777".into(),
        socket_addr: route.clone(),
        version: "1.5.0".into(),
        webrtc_sdp_answer: answer.clone(),
        ..Default::default()
    });
    controlled.send(&message).await?;
    assert_eq!(
        receive(&mut controller)
            .await?
            .punch_hole_response()
            .webrtc_sdp_answer,
        answer
    );

    #[cfg(feature = "webrtc")]
    {
        offerer.set_remote_endpoint(&answer).await?;
        let mut off_ice = offerer
            .take_local_ice_rx()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("No offer ICE receiver"))?;
        let mut ans_ice = answerer
            .take_local_ice_rx()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("No answer ICE receiver"))?;
        let session = offerer.session_key().to_owned();
        let mut sent = 0;
        let mut received = 0;
        while let Ok(Some(candidate)) = hbb_common::timeout(500, off_ice.recv()).await {
            message.set_ice_candidate(IceCandidate {
                id: "777777".into(),
                session_key: session.clone(),
                candidate,
                ..Default::default()
            });
            controller.send(&message).await?;
            let forwarded = udp_receive(&mut udp).await?;
            let ice = forwarded.ice_candidate();
            assert_eq!(ice.session_key, session);
            answerer.add_remote_ice_candidate(&ice.candidate).await?;
            sent += 1;
        }
        let mut candidate_connection = secure(server, &pk).await?;
        while let Ok(Some(candidate)) = hbb_common::timeout(500, ans_ice.recv()).await {
            message.set_ice_candidate(IceCandidate {
                socket_addr: route.clone(),
                session_key: session.clone(),
                candidate,
                ..Default::default()
            });
            candidate_connection.send(&message).await?;
            let forwarded = receive(&mut controller).await?;
            let ice = forwarded.ice_candidate();
            assert_eq!(ice.session_key, session);
            offerer.add_remote_ice_candidate(&ice.candidate).await?;
            received += 1;
        }
        assert!(sent > 0 && received > 0);
        offerer.wait_connected(20000).await?;
        answerer.wait_connected(20000).await?;
        message.set_test_nat_request(TestNatRequest {
            serial: 123,
            ..Default::default()
        });
        offerer.send(&message).await?;
        let bytes = answerer
            .next_timeout(5000)
            .await
            .ok_or_else(|| hbb_common::anyhow::anyhow!("WebRTC timeout"))??;
        assert_eq!(
            RendezvousMessage::parse_from_bytes(&bytes)?
                .test_nat_request()
                .serial,
            123
        );
        offerer.set_raw();
        answerer.set_raw();
        offerer.send_raw(b"webrtc tunnel".to_vec()).await?;
        let bytes = answerer
            .next_timeout(5000)
            .await
            .ok_or_else(|| hbb_common::anyhow::anyhow!("WebRTC raw timeout"))??;
        assert_eq!(&bytes[..], b"webrtc tunnel");
        offerer.close().await;
        answerer.close().await;
        println!("PASS encrypted SDP/ICE signaling and WebRTC P2P data");
    }

    let ws_addr = SocketAddr::new(server.ip(), server.port() + 2);
    let mut ws = WsFramedStream::new(format!("ws://{ws_addr}"), None, None, 3000).await?;
    message.set_test_nat_request(TestNatRequest::new());
    ws.send(&message).await?;
    let bytes = ws
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("WS timeout"))??;
    assert!(
        RendezvousMessage::parse_from_bytes(&bytes)?
            .test_nat_response()
            .port
            > 0
    );
    println!("PASS WebSocket RDPX request/response");

    let mut ws_peer = WsFramedStream::new(format!("ws://{ws_addr}"), None, None, 3000).await?;
    message.set_register_pk(RegisterPk {
        id: "888888".into(),
        uuid: vec![8; 16].into(),
        pk: vec![8; 32].into(),
        ..Default::default()
    });
    ws_peer.send(&message).await?;
    let _ = ws_peer
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("WS registration timeout"))??;
    let mut ws_controller = secure(server, &pk).await?;
    message.set_punch_hole_request(PunchHoleRequest {
        id: "888888".into(),
        licence_key: key.trim().into(),
        webrtc_sdp_offer: "ws-offer".into(),
        ..Default::default()
    });
    ws_controller.send(&message).await?;
    let bytes = ws_peer
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("WS offer timeout"))??;
    assert_eq!(
        RendezvousMessage::parse_from_bytes(&bytes)?
            .punch_hole()
            .webrtc_sdp_offer,
        "ws-offer"
    );
    for candidate in ["candidate-1", "candidate-2"] {
        message.set_ice_candidate(IceCandidate {
            id: "888888".into(),
            session_key: "ws-session".into(),
            candidate: candidate.into(),
            ..Default::default()
        });
        ws_controller.send(&message).await?;
        let bytes = ws_peer
            .next_timeout(5000)
            .await
            .ok_or_else(|| hbb_common::anyhow::anyhow!("WS ICE timeout"))??;
        assert_eq!(
            RendezvousMessage::parse_from_bytes(&bytes)?
                .ice_candidate()
                .candidate,
            candidate
        );
    }
    println!("PASS WebSocket mediator offer and repeated ICE delivery");

    // The relay must forward the peer's wire frames without decoding them again.
    let mut left = FramedStream::new(relay, None, 3000).await?;
    let mut right = FramedStream::new(relay, None, 3000).await?;
    message.set_request_relay(RequestRelay {
        uuid: "rdpx-smoke".into(),
        licence_key: key.trim().into(),
        ..Default::default()
    });
    left.send(&message).await?;
    // hbbr sends no acknowledgement when it stores the first relay endpoint.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    right.send(&message).await?;
    message.set_test_nat_request(TestNatRequest {
        serial: 456,
        ..Default::default()
    });
    left.send(&message).await?;
    assert_eq!(receive(&mut right).await?.test_nat_request().serial, 456);
    right.send(&message).await?;
    assert_eq!(receive(&mut left).await?.test_nat_request().serial, 456);
    left.set_raw();
    right.set_raw();
    left.send_raw(b"raw tunnel".to_vec()).await?;
    assert_eq!(
        &right
            .next_timeout(5000)
            .await
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Raw tunnel timeout"))??[..],
        b"raw tunnel"
    );
    println!("PASS TCP relay and raw tunnel byte transparency");
    drop(left);
    drop(right);
    let relay_ws = SocketAddr::new(relay.ip(), relay.port() + 2);
    let mut left = FramedStream::new(relay, None, 3000).await?;
    let mut right = WsFramedStream::new(format!("ws://{relay_ws}"), None, None, 3000).await?;
    message.set_request_relay(RequestRelay {
        uuid: "rdpx-mixed".into(),
        licence_key: key.trim().into(),
        ..Default::default()
    });
    left.send(&message).await?;
    // hbbr sends no acknowledgement when it stores the first relay endpoint.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    right.send(&message).await?;
    let session_key = secretbox::gen_key();
    left.set_key(session_key.clone());
    right.set_key(session_key);
    message.set_test_nat_request(TestNatRequest {
        serial: 789,
        ..Default::default()
    });
    left.send(&message).await?;
    let bytes = right
        .next_timeout(5000)
        .await
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Mixed relay timeout"))??;
    assert_eq!(
        RendezvousMessage::parse_from_bytes(&bytes)?
            .test_nat_request()
            .serial,
        789
    );
    right.send(&message).await?;
    assert_eq!(receive(&mut left).await?.test_nat_request().serial, 789);
    println!("PASS encrypted TCP/WebSocket mixed relay both directions");
    Ok(())
}
