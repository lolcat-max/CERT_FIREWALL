import pydivert
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import struct
from collections import defaultdict
import requests
import socket
import threading
import time

# Initial whitelist
ALLOWED_CERTS = {
    "GOOGLE_GTS": "5C8B5A8C8E9A4B2A0D3F4D1E6F6A3B2E3D4A8E6B2D9D7E8F4E9C2A7D8B6E3A1F",
    "XCOM_DIGICERT": "369ED47089361E64448D426B306A0B2823239C2280688E2780486B4E5F0A8D5E",
    "NEWSCOMAU_CLOUDFLARE": "59DF6B2EBD8B7DCC9F8D2D7845A89A797D89AB22206C10352B57910E8D1E581D"
}

conn_state = defaultdict(lambda: "pending")
pending_certs = {}  # {conn_key: cert_fp} for download

def download_cert(hostname, port=443):
    """Fetch cert fingerprint from hostname"""
    try:
        context = requests.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                fp = cert.fingerprint(hashes.SHA256()).hex().upper()
                return fp
    except:
        return None

def save_whitelist():
    """Persist whitelist to file"""
    with open("cert_whitelist.txt", "w") as f:
        for name, fp in ALLOWED_CERTS.items():
            f.write(f"{name}: {fp}\n")

def load_whitelist():
    """Load from file"""
    try:
        with open("cert_whitelist.txt", "r") as f:
            for line in f:
                name, fp = line.strip().split(": ", 1)
                ALLOWED_CERTS[name] = fp
    except FileNotFoundError:
        pass

def key(packet):
    return (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port, packet.ip.protocol)

def parse_tls_cert(payload):
    if len(payload) < 50 or payload[0] != 0x16 or payload[5] != 0x02: return None
    pos = 5; msg_type = payload[pos]; pos += 1
    if msg_type != 11: return None
    msg_len = struct.unpack(">H", payload[pos:pos+2])[0]; pos += msg_len + 2
    if pos + 3 > len(payload): return None
    cert_len = struct.unpack(">H", payload[pos+1:pos+3])[0]; pos += 3
    if pos + cert_len > len(payload): return None
    try:
        cert = x509.load_der_x509_certificate(payload[pos:pos+cert_len], default_backend())
        return cert.fingerprint(hashes.SHA256()).hex().upper()
    except:
        return None

def is_client_hello(payload):
    return len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01

# Load existing whitelist
load_whitelist()
print(f"Loaded {len(ALLOWED_CERTS)} certs. Auto-adding unknown...")

with pydivert.WinDivert("tcp and tcp.DstPort == 443") as w:
    w.queue_len = 32768
    
    def cert_downloader():
        while True:
            conn_key, hostname = pending_certs.popitem() if pending_certs else (None, None)
            if hostname:
                print(f"Fetching cert")
                fp = download_cert(hostname)
                if fp:
                    ALLOWED_CERTS[f"{hostname.upper()}"] = fp
                    conn_state[conn_key] = "allowed"
                    print(f"✓ ADDED {hostname}: [{fp[:16]}...]")
                    save_whitelist()
            time.sleep(1)
    
    threading.Thread(target=cert_downloader, daemon=True).start()
    
    for packet in w:
        conn_key = key(packet)
        state = conn_state[conn_key]
        
        if is_client_hello(packet.tcp.payload):
            # Extract hostname from SNI (if present)
            hostname = "unknown"
            if len(packet.tcp.payload) > 45:
                hostname = packet.tcp.payload[43:-1].decode('utf-8', errors='ignore').split(',')[0]
            
            conn_state[conn_key] = "pending"
            pending_certs[conn_key] = hostname
            print(f"PENDING")
            w.send(packet)
            continue
        
        if state == "pending":
            cert_fp = parse_tls_cert(packet.tcp.payload)
            if cert_fp in ALLOWED_CERTS.values():
                site = next(k for k, v in ALLOWED_CERTS.items() if v == cert_fp)
                conn_state[conn_key] = "allowed"
                print(f"ALLOWED [{site}]: {conn_key}")
            w.send(packet)
            continue
        
        if state == "allowed":
            w.send(packet)
        else:
            print(f"BLOCKED: {conn_key}")
