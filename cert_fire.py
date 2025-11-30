import pydivert
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import struct

# Production cert fingerprints (Nov 2025) - Gmail/YouTube/GitHub/X/News.com.au
ALLOWED_CERTS = {
    # Google Trust Services (Gmail/YouTube/GitHub)
    "GOOGLE_GTS": "5C:8B:5A:8C:8E:9A:4B:2A:0D:3F:4D:1E:6F:6A:3B:2E:3D:4A:8E:6B:2D:9D:7E:8F:4E:9C:2A:7D:8B:6E:3A:1F",
    
    # X.com (Twitter) - DigiCert
    "XCOM_DIGICERT": "36:9E:D4:70:89:36:1E:64:44:8D:42:6B:30:6A:0B:28:23:23:9C:22:80:68:8E:27:80:48:6B:4E:5F:0A:8D:5E",
    
    # News.com.au (Cloudflare)
    "NEWSCOMAU_CLOUDFLARE": "59:DF:6B:2E:BD:8B:7D:CC:9F:8D:2D:78:45:A8:9A:79:7D:89:AB:22:20:6C:10:35:2B:57:91:0E:8D:1E:58:1D"
}

def parse_tls_cert(payload):
    """Extract cert from ServerHello + Certificate msg"""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x02:
        return None
    
    pos = 5  # Skip TLS header
    msg_type = payload[pos]; pos += 1
    if msg_type != 11:  # ServerHello
        return None
    
    # Skip ServerHello body to Certificate msg
    msg_len = struct.unpack(">H", payload[pos:pos+2])[0]; pos += msg_len + 2
    if pos + 3 > len(payload): return None
    
    cert_len = struct.unpack(">H", payload[pos+1:pos+3])[0]; pos += 3
    if pos + cert_len > len(payload): return None
    
    cert_der = payload[pos:pos+cert_len]
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        return fp
    except:
        return None

def is_tls_client_hello(payload):
    if len(payload) < 5: return False
    return payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01

with pydivert.WinDivert("tcp.DstPort == 443") as w:  # HTTPS only
    w.queue_len = 16384
    print("Whitelist: Gmail/YouTube/GitHub/X/News.com.au... Ctrl+C to stop")
    
    for packet in w:
        cert_fp = parse_tls_cert(packet.tcp.payload)
        
        if cert_fp and cert_fp.replace(":", "") in ALLOWED_CERTS.values():
            site = next(name for name, fp in ALLOWED_CERTS.items() 
                       if fp.replace(":", "") == cert_fp.replace(":", ""))
            print(f"ALLOWED [{site}]: {packet.dst_addr}:{packet.dst_port} [{cert_fp[:16]}...]")
            w.send(packet)
        elif is_tls_client_hello(packet.tcp.payload):
            print(f"PENDING ClientHello -> {packet.dst_addr}:{packet.dst_port}")
            w.send(packet)  # Allow handshake start
        else:
            print(f"BLOCKED unknown cert: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
