"""
Client-side TLS handshake functions.
Handles Client Hello, Key Exchange and ChangeCipherSpec messages.
"""

from dataclasses import dataclass
from typing import List, Optional
import logging

from scapy.layers.tls.handshake import (
    TLSClientHello, TLSCertificate, 
    TLSClientKeyExchange, TLSFinished
)
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, TLS_Ext_EncryptThenMAC,
    TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms,
    ServerName
)
from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_128_CBC_SHA256
from scapy.layers.tls.record import TLSChangeCipherSpec
from scapy.all import raw
from cryptography.hazmat.primitives import serialization

from tls.utils.crypto import (
    generate_random, generate_pre_master_secret,
    encrypt_pre_master_secret
)
from tls.utils.cert import load_cert
from tls.constants import TLSVersion, CERTS_DIR

class HandshakeError(Exception):
    """Base exception for handshake operations"""
    pass

class ClientHelloError(HandshakeError):
    """Raised when Client Hello fails"""
    pass

class KeyExchangeError(HandshakeError):
    """Raised when key exchange fails"""
    pass

class ChangeCipherSpecError(HandshakeError):
    """Raised when ChangeCipherSpec fails"""
    pass

@dataclass
class ClientExtensions:
    """TLS Client Extensions configuration"""
    server_name: str
    supported_groups: List[str] = None
    signature_algorithms: List[str] = None
    encrypt_then_mac: bool = True

    def get_extension_list(self) -> List:
        """Generate list of TLS extensions"""
        extensions = [
            TLS_Ext_ServerName(
                servernames=[ServerName(servername=self.server_name.encode())]
            )
        ]
        
        if self.encrypt_then_mac:
            extensions.append(TLS_Ext_EncryptThenMAC())
            
        if self.supported_groups:
            extensions.append(
                TLS_Ext_SupportedGroups(groups=self.supported_groups)
            )
            
        if self.signature_algorithms:
            extensions.append(
                TLS_Ext_SignatureAlgorithms(sig_algs=self.signature_algorithms)
            )
            
        return extensions

def create_client_hello(
    session,
    extensions: Optional[ClientExtensions] = None
) -> TLSClientHello:
    """
    Create Client Hello message.
    
    Args:
        session: TLS session instance
        extensions: Optional client extensions configuration
        
    Returns:
        TLSClientHello: Configured hello message
    """
    # Generate client random
    session.client_GMT_unix_time, session.client_random_bytes = generate_random()
    session.client_random = session.client_GMT_unix_time.to_bytes(4, 'big') + session.client_random_bytes
    logging.info(f"Generated client_random: {session.client_random.hex()}")

    # Use default extensions if none provided
    if not extensions:
        extensions = ClientExtensions(
            server_name=session.SNI,
            supported_groups=["x25519"],
            signature_algorithms=["sha256+rsa"]
        )

    return TLSClientHello(
        version=TLSVersion.TLS_1_2,
        ciphers=[TLS_RSA_WITH_AES_128_CBC_SHA256],
        ext=extensions.get_extension_list(),
        gmt_unix_time=session.client_GMT_unix_time,
        random_bytes=session.client_random_bytes
    )

def send_client_hello(session) -> bytes:
    """
    Send Client Hello message to initiate TLS handshake.
    
    Args:
        session: TLS session instance
        
    Returns:
        bytes: Raw packet data
        
    Raises:
        ClientHelloError: If hello message fails
    """
    try:
        client_hello = create_client_hello(session)
        session.send_to_server(client_hello)

        # Track handshake message
        raw_hello = raw(client_hello)
        session.handshake_messages.append(raw_hello)
        session.tls_context.msg = [client_hello]

        logging.info(f"Client Hello sent from {session.client_ip}")
        return session.send_tls_packet(
            session.client_ip, 
            session.server_ip, 
            session.client_port, 
            session.server_port, 
            is_handshake=True
        )

    except Exception as e:
        raise ClientHelloError(f"Failed to send Client Hello: {e}")

def prepare_client_certificate(session) -> TLSCertificate:
    """
    Prepare client certificate - empty or with actual certificate.
    
    Args:
        session: TLS session instance
        
    Returns:
        TLSCertificate: Certificate message (empty or with cert)
    """
    try:
        if session.use_client_cert:
            # שליחת תעודת לקוח אמיתית
            client_cert_path = CERTS_DIR / "client.crt"
            cert = load_cert(client_cert_path)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            return TLSCertificate(certs=[(len(cert_der), cert_der)])
        else:
            # שליחת תעודה ריקה
            logging.info("Sending empty certificate")
            return TLSCertificate(certs=[])
            
    except Exception as e:
        raise KeyExchangeError(f"Failed to prepare client certificate: {e}")

def send_client_key_exchange(session) -> bytes:
    """Handle client key exchange during TLS handshake."""
    try:
        # תמיד שלח תעודה (ריקה או מלאה)
        client_certificate = prepare_client_certificate(session)
        session.handshake_messages.append(raw(client_certificate))
        logging.info("Client certificate prepared")

        # המשך הקוד כרגיל...
        session.pre_master_secret = generate_pre_master_secret()
        session.encrypted_pre_master_secret = encrypt_pre_master_secret(
            session.pre_master_secret,
            session.server_public_key
        )

        if not isinstance(session.encrypted_pre_master_secret, bytes):
            session.encrypted_pre_master_secret = bytes(session.encrypted_pre_master_secret)

        logging.info(f"Encrypted pre_master_secret length: {len(session.encrypted_pre_master_secret)}")

        # Create key exchange message
        length_bytes = len(session.encrypted_pre_master_secret).to_bytes(2, 'big')
        client_key_exchange = TLSClientKeyExchange(
            exchkeys=length_bytes + session.encrypted_pre_master_secret
        )

        # תמיד שלח קודם את התעודה
        session.send_to_server(client_certificate)
        session.send_to_server(client_key_exchange)
        session.handshake_messages.append(raw(client_key_exchange))

        # Update TLS context
        session.tls_context.msg = [client_certificate, client_key_exchange]

        return session.send_tls_packet(
            session.client_ip,
            session.server_ip,
            session.client_port,
            session.server_port,
            is_handshake=True
        )

    except Exception as e:
        raise KeyExchangeError(f"Key exchange failed: {e}")

def send_client_change_cipher_spec(session) -> bytes:
    """
    Send Client ChangeCipherSpec and Finished messages.
    
    Args:
        session: TLS session instance
        
    Returns:
        bytes: Raw packet data
        
    Raises:
        ChangeCipherSpecError: If sending messages fails
    """
    try:
        # Compute verify data
        client_verify_data = session.prf.compute_verify_data(
            'client',
            'write',
            b''.join(session.handshake_messages),
            session.master_secret
        )

        # Create messages
        client_finished = TLSFinished(vdata=client_verify_data)
        change_cipher_spec = TLSChangeCipherSpec()

        # Send messages
        session.send_to_server(client_finished)
        session.send_to_server(change_cipher_spec)

        # Update handshake state
        session.handshake_messages.append(raw(client_finished))
        session.handshake_messages.append(raw(change_cipher_spec))
        session.tls_context.msg = [change_cipher_spec, client_finished]

        logging.info("Client ChangeCipherSpec and Finished messages sent")
        return session.send_tls_packet(
            session.client_ip,
            session.server_ip,
            session.client_port,
            session.server_port,
            is_handshake=True
        )

    except Exception as e:
        raise ChangeCipherSpecError(
            f"Failed to send ChangeCipherSpec: {e}"
        )