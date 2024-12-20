import asyncio
import pyshark
import sqlite3
from datetime import datetime
import signal
import sys
import subprocess
import os


#No UI
def create_database():
    """
    Creates a database to store packet details.
    """
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            src_port TEXT,
            dest_port TEXT,
            length INTEGER,
            payload TEXT
        )
    """)
    conn.commit()
    return conn

#No UI
def store_packet(conn, packet_data):
    """
    Stores a packet's details into the database.
    """
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets (timestamp, source_ip, dest_ip, protocol, src_port, dest_port, length, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, packet_data)
    conn.commit()

def capture_packets(interface, count, bpf_filter, output_file):
    """
    Captures packets in real-time, saves to .pcapng file, and stores their details in the database.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    conn = create_database()
    # Check if the file already exists and ask user if they want to overwrite
    if os.path.exists(output_file):
        overwrite = input(f"The file {output_file} already exists. Do you want to overwrite it? (y/n): ")
        if overwrite.lower() != 'y':
            print("Aborting capture...")
            return
        else:
            os.remove(output_file)  # Delete the existing file if overwriting

    # Create the file and set permissions to 777
    try:
        with open(output_file, 'w'):
            pass
        os.chmod(output_file, 0o777)  # Set permissions to 777
        print(f"Output file {output_file} created and permissions set to 777.")
    except Exception as e:
        print(f"Error creating or setting permissions for output file: {e}")
        return

    print(f"Starting packet capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter, output_file=output_file)
    capture.set_debug()
    capture.bpf_filter = bpf_filter
    capture.custom_parameters = ['-B', '10']

    try:
        # Capture packets synchronously
        for packet in capture.sniff_continuously(packet_count=count):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            try:
                # Extract details from packet
                if hasattr(packet, 'ip'):
                    source_ip = packet.ip.src
                    dest_ip = packet.ip.dst
                else:
                    source_ip = 'N/A'
                    dest_ip = 'N/A'

                protocol = 'N/A'
                src_port = 'N/A'
                dest_port = 'N/A'

                if hasattr(packet, 'tcp'):
                    protocol = 'TCP'
                    src_port = packet.tcp.srcport
                    dest_port = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    protocol = 'UDP'
                    src_port = packet.udp.srcport
                    dest_port = packet.udp.dstport

                length = getattr(packet, 'length', None)
                payload = getattr(packet, 'data', 'N/A')

                # Store the packet in the database
                store_packet(conn, (timestamp, source_ip, dest_ip, protocol, src_port, dest_port, length, payload))

                # Display detailed captured packet info
                print(f"\n[{timestamp}] {protocol} | {source_ip}:{src_port} -> {dest_ip}:{dest_port} | Length: {length}")
                print(f"Full Packet: {packet}")

            except AttributeError:
                pass

    except KeyboardInterrupt:
        # Gracefully handle the interrupt and stop the capture
        print("\nPacket capture interrupted by user.")
    except Exception as e:
        print(f"Error capturing packets: {e}")
    finally:
        capture.close()
        conn.close()
        print(f"Capture session closed. Packets saved to {output_file}.")
        
def display_stored_packets():
    """
    Displays packets stored in the database for offline analysis.
    """
    packetList = []
    conn = sqlite3.connect("packets.db")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packets")
        packets = cursor.fetchall()

        print("\nStored Packets:")
        for packet in packets:
            print(packet)
            packetList.append(packet)
    finally:
        conn.close()
        return packetList

def list_available_interfaces():
    """
    Lists the available network interfaces on the system.
    """
    print("\nAvailable interfaces:")
    try:
        # Use pyshark to get interfaces if possible
        interfaces = pyshark.LiveCapture().interfaces
        if interfaces:
            for idx, interface in enumerate(interfaces):
                print(f"{idx + 1}. {interface}")
            return interfaces
        else:
            # Fallback to system command if pyshark fails
            raise Exception("No interfaces found using pyshark.")
    except Exception:
        print("Falling back to system-level interface listing...")
        try:
            # Fallback to ip command on Linux
            result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True)
            output = result.stdout
            interfaces = [line.split(':')[1].strip() for line in output.splitlines()]
            for idx, interface in enumerate(interfaces):
                print(f"{idx + 1}. {interface}")
            return interfaces
        except Exception as e:
            print(f"Error fetching interfaces: {e}")
            sys.exit(1)

def signal_handler(signal, frame):
    """
    Handles termination signals for clean exit.
    """
    print("\nTermination signal received. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_protocol_filter():
    """
    Prompts the user to select a protocol filter or capture all protocols.
    """
    print("\nAvailable protocols to capture:")
    protocols = ["TCP", "UDP", "ICMP", "ALL"]
    for idx, protocol in enumerate(protocols, 1):
        print(f"{idx}. {protocol}")

    while True:
        try:
            choice = int(input("Choose a protocol to capture (1-4): "))
            if choice in range(1, 5):
                selected_protocol = protocols[choice - 1]
                return "" if selected_protocol == "ALL" else selected_protocol.lower()
            else:
                print("Invalid choice. Please select a valid protocol.")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Create or connect to the database
   

    try:
        print("Network Packet Capture and Analysis")
        print("1. Capture packets")
        print("2. View stored packets")
        choice = input("Choose an option (1 or 2): ")

        if choice == "1":
            # List available interfaces and let the user select one
            interfaces = list_available_interfaces()
            interface_choice = int(input(f"Choose an interface (1 to {len(interfaces)}): "))
            interface = interfaces[interface_choice - 1]

            # Get protocol filter
            bpf_protocol_filter = get_protocol_filter()
            bpf_filter = bpf_protocol_filter

            # Ask for the number of packets to capture
            while True:
                try:
                    packet_count = int(input("Enter the number of packets to capture: "))
                    if packet_count > 0:
                        break
                    else:
                        print("Packet count must be greater than 0.")
                except ValueError:
                    print("Invalid input. Please enter a positive integer.")

            # Ask for output file name to save packets in .pcapng format
            output_file = input("Enter output file name (with .pcapng extension): ")

            # Capture packets synchronously and save them to a .pcapng file
            capture_packets(interface, packet_count,  bpf_filter, output_file)
            
        elif choice == "2":
            display_stored_packets()
        else:
            print("Invalid choice. Exiting.")
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
    finally:
        print("Exiting...")

def getInterfaces():
    interfaces = list_available_interfaces()
    return interfaces

def getProtocol():
    bpf_protocol_filter = get_protocol_filter()
    return bpf_protocol_filter
