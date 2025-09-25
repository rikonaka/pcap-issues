use ctrlc;
use pcap::Capture;
use pcap::Device;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Display the return packets of a specific host and port
fn show_sp_packet(data: &[u8], watch_ip: Ipv4Addr, watch_ports: &[u16]) -> Option<u16> {
    match EthernetPacket::new(data) {
        Some(ethernet_packet) => match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => {
                    let packet_src_ipv4_addr = ipv4_packet.get_source();
                    if packet_src_ipv4_addr == watch_ip {
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                match TcpPacket::new(ipv4_packet.payload()) {
                                    Some(tcp_packet) => {
                                        let dst_port = tcp_packet.get_source();
                                        if watch_ports.contains(&dst_port) {
                                            println!(
                                                "recv data from {}:{}",
                                                watch_ip,
                                                tcp_packet.get_source()
                                            );
                                        }
                                        Some(dst_port)
                                    }
                                    None => None,
                                }
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                None => None,
            },
            _ => None,
        },
        None => None,
    }
}

fn main() {
    let buffer_size = 163840;
    let snaplen = 65535;

    let device_name = "ens33"; // debian 13

    let devices = Device::list().expect("can not get device from libpcap");
    let device = devices
        .iter()
        .find(|&d| d.name == device_name)
        .expect("can not found interface");

    let cap = Capture::from_device(device.clone()).expect("init the Capture failed");

    let mut cap = cap
        .buffer_size(buffer_size)
        .snaplen(snaplen)
        .open()
        .expect("can not open libpcap capture");

    let watch_ip = Ipv4Addr::new(192, 168, 5, 152);
    let watch_ports = [22, 80, 100, 3333, 8080];

    let mut returned_ports = Vec::new();
    let all_ports: Vec<u16> = (22..65535).collect();

    // capturing the ctrl-c signal
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("quitting...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(p) => match show_sp_packet(&p.to_vec(), watch_ip, &watch_ports) {
                Some(port) => {
                    returned_ports.push(port);
                }
                None => (),
            },
            Err(e) => match e {
                pcap::Error::TimeoutExpired => {
                    println!("timeout expired, continue");
                    continue;
                }
                _ => panic!("get next packet failed: {}", e),
            },
        };
    }

    println!("now all returned ports length is: {}", returned_ports.len());

    let mut missing_ports = Vec::new();
    for sp in all_ports {
        if !returned_ports.contains(&sp) {
            missing_ports.push(sp);
        }
    }
    println!("missing ports: {:?}", missing_ports);
}
