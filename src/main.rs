use std::io::{Cursor, Read};
use std::{any::type_name_of_val, path::PathBuf};
use std::fs::File;

use clap::{Parser};

use packet_parser::parse::data_link::DataLink;
use packet_parser::parse::internet::protocols::ipv4::Ipv4Packet;
use packet_parser::parse::transport::protocols::tcp::TcpPacket;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional output filename
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    output_file: Option<PathBuf>,

    /// Input pcap/pcapng file
    input_file: PathBuf,
}

fn handle_packets(packet: &[u8]) {
    match DataLink::try_from(packet){
        Ok(datalink) => {
            match Ipv4Packet::try_from(datalink.payload) {
                Ok(ipv4packet) => {
                    match TcpPacket::try_from(ipv4packet.payload) {
                        Ok(tcppacket) => {
                            println!("{:?}", tcppacket)
                        },
                        Err(e) => eprintln!("[Transport] Parsing error: {:?} (ipv4 packet id: {1})", e, ipv4packet.identification)
                    }
                },
                Err(e) => eprintln!("[Network] Parsing error: {:?}", e)
            }
        },
        Err(e) => eprintln!("[DataLink] Parsing error: {:?}", e)
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(output_file) = cli.output_file.as_deref() {
        let path = output_file.file_name().and_then(|name| name.to_str()).unwrap();
        println!("Path of output_file: {path}");
    }
    
    let mut file_in = File::open(cli.input_file).expect("Error opening file");

    let mut buffer = [0u8; 4];

    let _ = file_in.read_exact(&mut buffer);

    let stream_with_magic = Cursor::new(buffer).chain(file_in);

    match buffer {
        [0x0A, 0x0D, 0x0D, 0x0A] => {
            let mut pcapng_reader = PcapNgReader::new(stream_with_magic).unwrap();

            while let Some(block) = pcapng_reader.next_block() {
                // Check if there is no error
                let block = block.unwrap();

                match block {
                    Block::EnhancedPacket(packet) => {
                        handle_packets(packet.data.as_ref());
                    },
                    _ => {
                        println!("{}", type_name_of_val(&block))
                    }
                }

            } 

        },
        _ => {
            let mut pcap_reader = PcapReader::new(stream_with_magic).unwrap();

            while let Some(packet) = pcap_reader.next_packet() {
                let packet = packet.unwrap();
                handle_packets(packet.data.as_ref());
            }
        }
    }


}

