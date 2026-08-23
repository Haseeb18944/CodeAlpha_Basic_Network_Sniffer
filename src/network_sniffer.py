#!/usr/bin/env python3

"""
CodeAlpha Basic Network Sniffer

A defensive network traffic analysis tool built with Scapy.
It captures packets from an authorized network interface and
displays useful metadata such as:

- Timestamp
- Source IP
- Destination IP
- Protocol
- Source/Destination ports
- Packet length
- Payload size
- Safe hexadecimal payload preview

Use only on networks and systems you are authorized to monitor.
"""

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime

from scapy.all import (
    ICMP,
    IP,
    TCP,
    UDP,
    get_if_list,
    sniff,
)


class NetworkSniffer:
    """Network packet capture and analysis engine."""

    def __init__(self, interface=None, packet_filter=None, output=None):
        self.interface = interface
        self.packet_filter = packet_filter
        self.output = output

        self.packet_count = 0
        self.protocol_stats = Counter()

        self.csv_file = None
        self.csv_writer = None

        if self.output:
            self._initialize_csv()

    def _initialize_csv(self):
        """Create the optional CSV metadata report."""

        self.csv_file = open(
            self.output,
            "w",
            newline="",
            encoding="utf-8",
        )

        fieldnames = [
            "timestamp",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "packet_length",
            "payload_size",
            "payload_preview",
        ]

        self.csv_writer = csv.DictWriter(
            self.csv_file,
            fieldnames=fieldnames,
        )

        self.csv_writer.writeheader()

    @staticmethod
    def identify_protocol(packet):
        """Identify the primary transport/control protocol."""

        if packet.haslayer(TCP):
            return "TCP"

        if packet.haslayer(UDP):
            return "UDP"

        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(IP):
            return "IP"

        return "OTHER"

    @staticmethod
    def get_ports(packet):
        """Return source and destination ports when available."""

        source_port = "-"
        destination_port = "-"

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        return source_port, destination_port

    @staticmethod
    def get_payload_preview(packet):
        """
        Return payload size and a short hexadecimal preview.

        Only a small preview is displayed; complete payload contents
        are not printed or stored.
        """

        payload = b""

        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)

        elif packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)

        elif packet.haslayer(ICMP):
            payload = bytes(packet[ICMP].payload)

        payload_size = len(payload)

        # Display only the first 16 bytes.
        preview = payload[:16].hex(" ")

        if not preview:
            preview = "-"

        return payload_size, preview

    def process_packet(self, packet):
        """Analyze and display one captured packet."""

        if not packet.haslayer(IP):
            return

        self.packet_count += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = self.identify_protocol(packet)

        source_port, destination_port = self.get_ports(packet)

        packet_length = len(packet)

        payload_size, payload_preview = self.get_payload_preview(packet)

        self.protocol_stats[protocol] += 1

        print(
            f"[{self.packet_count:04d}] "
            f"{timestamp} | "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} | "
            f"{protocol:<5} | "
            f"Length: {packet_length:<5} | "
            f"Payload: {payload_size:<5}"
        )

        if payload_size > 0:
            print(
                f"       Payload preview: "
                f"{payload_preview}"
            )

        if self.csv_writer:
            self.csv_writer.writerow(
                {
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "packet_length": packet_length,
                    "payload_size": payload_size,
                    "payload_preview": payload_preview,
                }
            )

            self.csv_file.flush()

    def start(self, count=0, duration=None):
        """Start packet capture."""

        print("=" * 90)
        print("                 CodeAlpha Basic Network Sniffer")
        print("=" * 90)

        print(f"Interface : {self.interface or 'Default'}")
        print(f"Filter    : {self.packet_filter or 'None'}")
        print(f"Count     : {count if count > 0 else 'Unlimited'}")
        print(
            f"Duration  : "
            f"{str(duration) + ' seconds' if duration else 'Unlimited'}"
        )

        print("-" * 90)
        print("Capturing packets...")
        print("Press Ctrl+C to stop.")
        print("-" * 90)

        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self.process_packet,
                store=False,
                count=count,
                timeout=duration,
            )

        except PermissionError:
            print(
                "\n[ERROR] Permission denied."
                "\nRun the sniffer with appropriate privileges."
            )

        except Exception as error:
            print(
                f"\n[ERROR] Capture failed: {error}"
            )

        finally:
            self.stop()

    def stop(self):
        """Close resources and display final statistics."""

        if self.csv_file:
            self.csv_file.close()

        print("\n" + "=" * 90)
        print("                    Capture Summary")
        print("=" * 90)

        print(f"Total packets analyzed: {self.packet_count}")

        if self.protocol_stats:
            print("\nProtocol statistics:")

            for protocol, count in self.protocol_stats.most_common():
                print(f"  {protocol:<8}: {count}")

        else:
            print("No IPv4 packets were analyzed.")

        if self.output:
            print(f"\nCSV report: {self.output}")

        print("=" * 90)


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture from",
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)",
    )

    parser.add_argument(
        "-t",
        "--duration",
        type=int,
        help="Capture duration in seconds",
    )

    parser.add_argument(
        "-f",
        "--filter",
        dest="packet_filter",
        help="Optional BPF filter, e.g. 'tcp' or 'icmp'",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional CSV report path",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display available network interfaces",
    )

    return parser.parse_args()


def main():
    """Application entry point."""

    args = parse_arguments()

    if args.list_interfaces:
        print("\nAvailable network interfaces:\n")

        for interface in get_if_list():
            print(f"  - {interface}")

        sys.exit(0)

    if args.count < 0:
        print("[ERROR] Packet count cannot be negative.")
        sys.exit(1)

    if args.duration is not None and args.duration <= 0:
        print("[ERROR] Duration must be greater than zero.")
        sys.exit(1)

    sniffer = NetworkSniffer(
        interface=args.interface,
        packet_filter=args.packet_filter,
        output=args.output,
    )

    sniffer.start(
        count=args.count,
        duration=args.duration,
    )


if __name__ == "__main__":
    main()
