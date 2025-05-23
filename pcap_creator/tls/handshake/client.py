"""
Client-side TLS handshake functions.
Handles Client Hello, Key Exchange and ChangeCipherSpec messages.
"""
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_128_CBC_SHA256
from scapy.layers.tls.record import TLSChangeCipherSpec
from scapy.layers.tls.handshake import (
    TLSClientHello, TLSCertificate, 
    TLSClientKeyExchange, TLSFinished
)
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, TLS_Ext_EncryptThenMAC,
    TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms,
    ServerName
)
from scapy.all import raw
from dataclasses import dataclass
from typing import List, Optional
import logging
import os

from ..constants import TLSVersion, CERTS_DIR
from ..crypto.keys import KeyBlock
from ..utils.cert import load_cert
from ..utils.crypto import (
    generate_pre_master_secret,
    encrypt_pre_master_secret,decrypt_pre_master_secret,
    compare_to_original, encrypt_finished_message
    
)

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
    #cipher_suites = [session.cipher_suite.id]
    
    # Generate client random as one piece
    session.client_random = os.urandom(32)  # Generate all 32 bytes at once
    logging.info(f"Generated client_random: {session.client_random.hex()}")

    # Extract GMT time and random bytes for TLSClientHello
    gmt_time = int.from_bytes(session.client_random[:4], 'big')
    random_bytes = session.client_random[4:]

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
        gmt_unix_time=gmt_time,
        random_bytes=random_bytes
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

def create_client_certificate_and_key_exchange(
        session
        ) -> tuple[TLSCertificate, TLSClientKeyExchange]:
    """
    Creates client certificate and key exchange messages for TLS handshake.
    
    Args:
        session: TLS session instance containing configuration and state
        
    Returns:
        tuple[TLSCertificate, TLSClientKeyExchange]: The prepared messages
        
    Raises:
        KeyExchangeError: If message creation fails
    """
    try:
        # Prepare client certificate
        if session.use_client_cert:
            client_cert_path = CERTS_DIR / "client.crt"
            cert = load_cert(client_cert_path)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            client_certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])
            logging.info("Prepared client certificate")
        else:
            client_certificate = TLSCertificate(certs=[])
            logging.info("Prepared empty certificate")

        # Generate and encrypt pre-master secret
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

        return client_certificate, client_key_exchange

    except Exception as e:
        raise KeyExchangeError(f"Failed to create handshake messages: {e}")

def send_client_handshake_messages(session) -> bytes:
    """
    Creates and sends client certificate and key exchange messages during TLS handshake.
    
    Args:
        session: TLS session instance
        
    Returns:
        bytes: Raw packet data
        
    Raises:
        KeyExchangeError: If message creation or sending fails
    """
    try:
        # Create messages
        client_certificate, client_key_exchange = create_client_certificate_and_key_exchange(session)

        # Append messages to handshake history
        session.handshake_messages.extend([
            raw(client_certificate),
            raw(client_key_exchange)
        ])

        # Send messages
        session.send_to_server(client_certificate)
        session.send_to_server(client_key_exchange)

        # Update TLS context
        session.tls_context.msg = [client_certificate, client_key_exchange]

        # Send TLS packet
        return session.send_tls_packet(
            session.client_ip,
            session.server_ip,
            session.client_port,
            session.server_port,
            is_handshake=True
        )

    except Exception as e:
        raise KeyExchangeError(f"Failed to send handshake messages: {e}")

def create_client_finished(session) -> tuple[TLSFinished, TLSChangeCipherSpec]:
    """
    Creates Server Finished and ChangeCipherSpec messages.
    
    Args:
        session: TLS session instance
        
    Returns:
        tuple[TLSFinished, TLSChangeCipherSpec]: The finished and change cipher spec messages
        
    Raises:
        ChangeCipherSpecError: If message creation fails
    """
    try:
        # Verify pre-master secret
        decrypted_pre_master_secret = decrypt_pre_master_secret(
            session.encrypted_pre_master_secret,
            session.server_private_key
        )
        
        if not compare_to_original(
            decrypted_pre_master_secret,
            session.pre_master_secret
        ):
            raise ChangeCipherSpecError("Pre-master secret validation failed")
            
        logging.info("Pre-master secret validated successfully")
        logging.debug(f"Decrypted pre-master secret: {decrypted_pre_master_secret.hex()}")

        # Compute verify data
        client_verify_data = session.prf.compute_verify_data(
            'client',
            'write',
            b''.join(session.handshake_messages),
            session.master_secret
        )

        # Generate signature
        signature_data = client_verify_data + b''.join(session.handshake_messages)
        signature = session.server_private_key.sign(
            signature_data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        logging.info(f"Generated digital signature: {signature.hex()}")

        # Create messages
        change_cipher_spec = TLSChangeCipherSpec()
        client_finished = TLSFinished(vdata=client_verify_data)

        # Encrypt finished message using client key
        key_block = KeyBlock.derive(session)
        client_finished_encrypted = encrypt_finished_message(
            client_finished,
            key_block.client_key,
            key_block.client_iv
        )
        return change_cipher_spec, client_finished_encrypted

    except Exception as e:
        raise ChangeCipherSpecError(f"Failed to create finished messages: {e}")

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
         # Create messages
        change_cipher_spec, client_finished = create_client_finished(session)

         # Send messages
        session.send_to_server(change_cipher_spec)
        session.send_to_server(client_finished)

        # Update handshake state
        session.handshake_messages.append(raw(change_cipher_spec))
        session.handshake_messages.append(raw(client_finished))

        # Update TLS context
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
        raise ChangeCipherSpecError(f"Failed to send ChangeCipherSpec: {e}")
    
