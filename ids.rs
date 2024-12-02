use pnet::datalink::{self, NetworkInterface};   //alows capturing raw packets on network interface
use pnet::packet::ip::IpNextHeaderProtocols;  
use pnet::packet::ipv4::Ipv4Packet; // ipv4,Tcppacket handle ipv4 and tcp packet parsing
use pnet::packet::tcp::TcpPacket;  
use pnet::packet::{Packet, ethernet::EthernetPacket}; //Access ethernet frame data
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// A structure to store detected activities
#[derive(Debug)]
struct DetectionLog {
    source_ip: IpAddr,
    detected_activity: String,
    timestamp: Instant,
}

// Main function
fn main() {
    // Step 1: Get the list of available network interfaces
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No suitable network interface found");
/*step1 fetches all available network interfaces and selects one that is active and not loopback interface*/

    println!("Using interface: {}", interface.name);

    // Step 2: Open a channel to capture packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Step 3: Shared storage for detected activities
    let detection_logs: Arc<Mutex<Vec<DetectionLog>>> = Arc::new(Mutex::new(Vec::new()));
    let logs = detection_logs.clone();

    // Step 4: Start a background thread to monitor the logs
    thread::spawn(move || loop {
        let logs = logs.lock().unwrap();
        for log in logs.iter() {
            println!(
                "[ALERT] {} detected from {} at {:?}",
                log.detected_activity, log.source_ip, log.timestamp
            );
        }
        thread::sleep(Duration::from_secs(5));
    });

    // Step 5: Start capturing packets
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                    analyze_packet(ip_packet, &detection_logs);
                }
            }
            Err(e) => {
                eprintln!("Failed to read packet: {}", e);
            }
        }
    }
}

// Function to analyze captured packets
fn analyze_packet(packet: Ipv4Packet, logs: &Arc<Mutex<Vec<DetectionLog>>>) {
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();
    let protocol = packet.get_next_level_protocol();

    // Detect port scanning (TCP SYN packets)
    if protocol == IpNextHeaderProtocols::Tcp {
        if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
            if tcp_packet.get_flags() == 0x02 { // SYN flag
                let log = DetectionLog {
                    source_ip: IpAddr::V4(src_ip),
                    detected_activity: "Port Scanning Attempt".to_string(),
                    timestamp: Instant::now(),
                };
                logs.lock().unwrap().push(log);
            }
        }
    }

    // Detect DoS-like behavior (high-frequency traffic)
    {
        static mut DOS_TRACKER: HashMap<IpAddr, usize> = HashMap::new();
        unsafe {
            let counter = DOS_TRACKER.entry(IpAddr::V4(src_ip)).or_insert(0);
            *counter += 1;
            if *counter > 100 {
                let log = DetectionLog {
                    source_ip: IpAddr::V4(src_ip),
                    detected_activity: "Possible DoS Attack".to_string(),
                    timestamp: Instant::now(),
                };
                logs.lock().unwrap().push(log);
                *counter = 0; // Reset counter
            }
        }
    }
}

