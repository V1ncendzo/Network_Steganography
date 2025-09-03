# Network Steganography Project

## Overview
This capstone project explores covert communication by embedding RSA-encrypted messages into the destination port numbers of TCP packets. It creates a stealthy channel between a sender and receiver, blending with normal traffic to evade detection by passive observers like network monitors.

## Key Features
- **Encryption**: Uses RSA (asymmetric) with the receiver's public key for message security.
- **Embedding**: Divides encrypted message into bits, embeds each into TCP destination ports; payload length indicates bit position.
- **Transmission**: Sender crafts and sends TCP packets; receiver extracts bits, reassembles, and decrypts with private key.
- **Stealth**: Designed to mimic legitimate traffic, resistant to statistical detection.
- **Implementation**: Python-based sender (`sender.py`) and receiver (`receiver.py`) scripts.

## Requirements
- Python 3.x
- Libraries: Scapy (for packet crafting), Cryptography (for RSA), and standard modules like socket, random.
- RSA key pair: Public key for sender, private key for receiver (generated if needed).

## Usage
### Setup
1. Generate RSA keys (receiver side): Run receiver script first to create `private.pem` and `public.pem`.
2. Share `public.pem` with sender.

### Sender (sender.py)
- Run: `python sender.py`
- Input: Destination IP, message to send, optional payload file (or random payload generated).
- Sends crafted TCP packets with embedded bits; ends with a special indicator packet.

### Receiver (receiver.py)
- Run: `python receiver.py`
- Listens on network interface (e.g., via Scapy's `sniff`).
- Extracts bits from incoming TCP packets, reassembles encrypted message, decrypts, and displays plaintext.

## Evaluation
- **Stealthiness**: Undetectable by tools like Wireshark under standard monitoring.
- **Reliability**: Successful message transmission and decryption in controlled tests.
- **Limitations**: Suited for small/moderate messages; bandwidth balances stealth vs. data volume.

## Contributors
- Group 1: Nguyen Duc Thang (20210778), Nguyen Hoang Anh (20214945), Nguyen Huu Duan (20214951), Nguyen Huy Hoang (20214959)
- Lecturers: Mr. Tran Quanh Duc, Mr. Le Van Dong

Hanoi University of Science and Technology, 01/2024. For details, refer to the full report.
