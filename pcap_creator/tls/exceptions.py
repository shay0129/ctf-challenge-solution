"""
Custom exceptions for TLS session handling.
Contains exception hierarchy for different types of TLS-related errors.
"""

class TLSError(Exception):
    """Base exception for all TLS-related errors"""
    pass

# Session Errors
class TLSSessionError(TLSError):
    """Base exception for session-related errors"""
    pass

class SessionInitError(TLSSessionError):
    """Raised when session initialization fails"""
    pass

class HandshakeError(TLSSessionError):
    """Raised when TLS handshake fails"""
    pass

class SessionCleanupError(TLSSessionError):
    """Raised when session cleanup fails"""
    pass

# Configuration Errors
class ConfigurationError(TLSError):
    """Base exception for configuration-related errors"""
    pass

class InvalidConfigError(ConfigurationError):
    """Raised when configuration validation fails"""
    pass

class PathConfigError(ConfigurationError):
    """Raised when file path configuration is invalid"""
    pass

# Cryptographic Errors
class CryptoError(TLSError):
    """Base exception for cryptographic operations"""
    pass

class KeyGenerationError(CryptoError):
    """Raised when key generation fails"""
    pass

class EncryptionError(CryptoError):
    """Raised when encryption operations fail"""
    pass

class DecryptionError(CryptoError):
    """Raised when decryption operations fail"""
    pass

# Certificate Errors
class CertificateError(TLSError):
    """Base exception for certificate operations"""
    pass

class CertLoadError(CertificateError):
    """Raised when certificate loading fails"""
    pass

class CertValidationError(CertificateError):
    """Raised when certificate validation fails"""
    pass

class CertChainError(CertificateError):
    """Raised when certificate chain validation fails"""
    pass

# Protocol Errors
class ProtocolError(TLSError):
    """Base exception for protocol-related errors"""
    pass

class RecordLayerError(ProtocolError):
    """Raised when TLS record layer operations fail"""
    pass

class AlertError(ProtocolError):
    """Raised when TLS alert is received"""
    pass

# Network Errors
class NetworkError(TLSError):
    """Base exception for network-related errors"""
    pass

class PacketError(NetworkError):
    """Raised when packet operations fail"""
    pass

class PCAPError(NetworkError):
    """Raised when PCAP operations fail"""
    pass

# Utility Errors
class UtilityError(TLSError):
    """Base exception for utility operations"""
    pass

class LoggingError(UtilityError):
    """Raised when logging operations fail"""
    pass

class ValidationError(UtilityError):
    """Raised when validation operations fail"""
    pass

# Helper function to get error details
def get_error_details(error: Exception) -> str:
    """
    Get detailed error information.
    
    Args:
        error: The exception to analyze
        
    Returns:
        str: Formatted error details
    """
    return (f"Error Type: {type(error).__name__}\n"
            f"Error Message: {str(error)}\n"
            f"Error Args: {error.args}")

# Additional helper functions for error handling
def handle_session_error(error: Exception, session_id: str = None) -> TLSSessionError:
    """
    Handle and convert session-related errors.
    
    Args:
        error: Original exception
        session_id: Optional session identifier
        
    Returns:
        TLSSessionError: Wrapped exception with context
    """
    context = f" in session {session_id}" if session_id else ""
    return TLSSessionError(f"Session error{context}: {str(error)}")

def handle_crypto_error(error: Exception, operation: str = None) -> CryptoError:
    """
    Handle and convert cryptographic errors.
    
    Args:
        error: Original exception
        operation: Optional operation description
        
    Returns:
        CryptoError: Wrapped exception with context
    """
    context = f" during {operation}" if operation else ""
    return CryptoError(f"Cryptographic error{context}: {str(error)}")

def handle_network_error(error: Exception, address: str = None) -> NetworkError:
    """
    Handle and convert network-related errors.
    
    Args:
        error: Original exception
        address: Optional network address
        
    Returns:
        NetworkError: Wrapped exception with context
    """
    context = f" with {address}" if address else ""
    return NetworkError(f"Network error{context}: {str(error)}")