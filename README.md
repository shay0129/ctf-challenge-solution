# my CTF - BackGround

This repository provides a simple implementation of ...
![alt text](pcap-image.png)
## Table of Contents

- [Frame story](#frame-story)
- [Subjects](#subjects)
- [Challenge Steps](#challenge-steps)
- [Usage](#usage)
  - [PCAP Creation](#pcap-creation)
    - [TLS Handshake Steps](#tls-handshake-steps)
    - [Client Hello](#client-hello)
    - [Server Hello](#server-hello)
    - [Client Key Exchange](#client-key-exchange)
    - [Calculate Master Secret](#calculate-master-secret)
    - [Client Change Cipher Spec](#client-change-cipher-spec)
    - [Server Change Cipher Spec](#server-change-cipher-spec)
    - [Create SSLKeyLog File](#create-sslkeylog-file)
    - [Application Data Encryption](#application-data-encryption)
      - [issue](#issue)
  - [Create Communication](#create-communication)
    - [Server File](#server-file)
    - [Client no-cert File](#client-no-cert-file)
    - [Client cert File](#client-cert-file)
    - [Protocol File](#protocol-file)
- [Building and Integration](#building-and-integration)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

## Challenge Description

The challenge is themed around the Ritchie Boys, a historical group of German-born individuals recruited by the US Army in World War II for intelligence and psychological warfare against Nazi Germany.
In the context of the challenge, the Ritchie Boys Force is revived in 2025 to combat Iran's Islamic Revolutionary Guard Corps.
The player's goal is to compromise an Iranian server and extract the encryption key used for the organization's radio communications.

## Subjects
The challenge covers various skills including:
1. Wireshark: Network traffic analysis
2. Python scripting: PCAP Creation with Scapy, Socket programming.
3. Operating System knowledge: PE format understanding
4. Cryptography: Encryption keys and file decryption
5. HTTP protocol: Analysis and bug identification
6. Reverse Engineering: Embedding exe in pdf.
7. PCAP creation with Scapy.
8. Protocol analysis tools: TShark and OpenSSL in WSL environment

## Challenge Steps

1. Revealing the Files

- Start with mission.pdf
- Extract hidden files:
    - server.exe
    - Corrupted client.exe
- Use steganography techniques

2. Client Fix
- Run server.exe to get encryption key (random character sequence)
- Write Python script to decrypt client.exe
- Make client.exe executable

3. Communication Analysis
- Run server.exe and client.exe simultaneously
- Analyze capture.pcapng from mission.pdf
- Discover server's requirement: send resource only to clients with Certificate during TLS Handshake

4.  Creating Another Client
- Create client2.exe
- Must connect concurrently with original client
- Ensure client2.exe is unique to avoid server treating it as duplicate
- Difference: client1 doesn't load certificate, client2 does

5. Self-Signed Certificate
- Generate self-signed certificate without CA
- Integrate certificate into client2 code
- Ensure server recognizes certificate during TLS handshake
- Possible localhost domain setup
- Be prepared for server expecting DER format instead of CRT

6. CRS File Verification
- After loading certificate, client2 must also load CRS file
- Verifies proper certificate creation steps
- Prevents bypass using Python script

7. Capturing the Resource
- client2 receives resource.png from server
- Image contains flag in plain sight
- Participants submit flag to complete challenge

## Usage

### PE stole
PDF Structure Hint

The PDF file contains two hidden executables:

1. server.exe: A standard PE file
2. client1.exe: An encrypted PE file

Structure:
[PDF Content]
[server.exe (PE format)]
[Magic Number: 0xDEADBEEF + Encrypted Key]
[Encrypted client1.exe]

Hint: 
- Look for the PE header to find the start of server.exe. 
- The magic number 0xDEADBEEF marks the end of server.exe and the start of the encrypted client1.exe.
- The encryption key for client1.exe is hidden within the magic number itself.

Challenge:
Can you find the encryption key hidden in the magic number? 
It's not just 0xDEADBEEF - there's more to it!


### PCAP Creation
Code for generating the PCAP file using Scapy, simulating the TLS handshake and application data exchange between the client and server.
```python
def main():
    config = Config()
    writer = CustomPcapWriter(config)
    # clear the SSL_KEYLOG_FILE
    with open(config.SSL_KEYLOG_FILE, "w") as f:
        pass

    logging.info("\n--- Client 1 Session ---")
    client1_session = UnifiedTLSSession(writer, config.CLIENT1_IP, config.SERVER_IP, 12345, 443, use_tls=True, use_client_cert=True)
    client1_session.run_session(config.GET_REQUEST, config.OK_RESPONSE, 'flag.jpeg')
    client1_session.verify_tls_session()  # Verify TLS session for Client 1

    logging.info("\n--- Client 2 Session ---")
    client2_session = UnifiedTLSSession(writer, config.CLIENT2_IP, config.SERVER_IP, 12346, 443, use_tls=True, use_client_cert=False)
    client2_session.run_session(config.GET_REQUEST, config.BAD_REQUEST)

    writer.save_pcap(config.OUTPUT_PCAP)
    writer.verify_and_log_packets()

```
Explain:
Client01 do TLS Handshake with the server while sending Cleint Cert.
Client01 ask a resource from the server, and he send it.
The connection between them after handshake is secure.
Client02 do TLS Handshake without send Client cert.
Client02 ask a resource from the server, and he dont send it, but send 400 status code.
The connection between them after handshake is not secure.

### TLS Handshake Steps
TLS Handshake Steps: Functions for each step of the TLS handshake, including ClientHello, ServerHello, key exchange, and setting up secure communication.
```python
def perform_handshake(self)-> None:
        # According to RFC 5246, the TLS handshake process is as follows:
        try:
            # Step 1: Client Hello
            self.send_client_hello()
            
            # Step 2: Server Hello, Certificate, ServerKeyExchange (if needed), ServerHelloDone
            self.send_server_hello()
            
            # Step 3: Client (RSA) Key Exchange (and Client Certificate if required)
            self.send_client_key_exchange()
            
            # Step 4: Generate Master Secret
            self.handle_master_secret()
            
            # Step 5: Client ChangeCipherSpec and Finished
            self.send_client_change_cipher_spec()
            
            # Step 6: Server ChangeCipherSpec and Finished
            self.send_server_change_cipher_spec()
            
            # Step 7: Log SSL keys for Wireshark
            self.handle_ssl_key_log()
            
            logging.info("TLS Handshake completed successfully")
        except Exception as e:
            logging.error(f"TLS Handshake failed: {str(e)}")
            raise e
```
Explain:
1. Client Hello - The client tell to server the encryption algorithms he support, and choose random bytes for idendify.
2. Server Hello -
3. Client key Exchange - Client send to server an encrypted shared key, that only server can decrypt it and calculate a main shared key.
4. Each side calculate this shared key. server - with a decrypted key and client with original key.
5. 

### Client Hello
```python
def send_client_hello(self)-> None:
        self.client_GMT_unix_time, self.client_random_bytes = generate_random()
        self.client_random = self.client_GMT_unix_time.to_bytes(4, 'big') + self.client_random_bytes
        
        client_hello = TLSClientHello(
            version=0x0303,  # TLS 1.2
            ciphers=[TLS_RSA_WITH_AES_128_CBC_SHA256],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername=f"{self.server_name}.local".encode())]),
                TLS_Ext_EncryptThenMAC(),
                TLS_Ext_SupportedGroups(groups=["x25519"]),
                TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"]),
            ],
            gmt_unix_time=self.client_GMT_unix_time,
            random_bytes=self.client_random_bytes
        )
        self.tls_context.msg = [client_hello]
        self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)
```
Explain:
Client Random Record included GMT unix time and random bytes.
Client is offer the ciphers he support (only one, in this case).
Client ...rsa???
#### Server Hello
```python
def send_server_hello(self)-> None:      
        self.server_GMT_unix_time, self.server_random_bytes = generate_random()
        self.server_random = self.server_GMT_unix_time.to_bytes(4, 'big') + self.server_random_bytes

        self.session_id = os.urandom(32)
        try:
            
            cert = load_cert(self.server_name+".pem")
            cert_der = cert.public_bytes(serialization.Encoding.PEM)
            # Extract the public key from the certificate
            self.server_public_key = cert.public_key()

        except Exception as e:
            logging.error(f"Error loading server certificate: {str(e)}")
            raise

        server_hello = TLSServerHello(
            version=0x0303,  # TLS 1.2
            gmt_unix_time=self.server_GMT_unix_time,
            random_bytes=self.server_random_bytes,
            sid = self.session_id,
            cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val,
            ext=[
                #TLS_Ext_ServerName(servernames=[ServerName(servername="Pasdaran.local")]), # need fix this extantion
                #TLS_Ext_SupportedGroups(groups=['secp256r1', 'x25519']), # relevant for ECDHE key exchange
                TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsaepss']),
                TLS_Ext_ExtendedMasterSecret(),
                TLS_Ext_EncryptThenMAC()
                ]
            )
        
        # Server Certificate
        certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])

        # Add this line to explicitly set the TLS version for the session
        self.tls_context.tls_version = 0x0303  # TLS 1.2

        self.tls_context.msg = [server_hello, certificate, TLSCertificateRequest(), TLSServerHelloDone()]
        self.send_tls_packet(self.server_ip, self.client_ip, self.server_port, self.client_port)
```
Explain:

#### Client Key Exchange
```python
def send_client_key_exchange(self)-> None:
        client_certificate = None
        if self.use_client_cert:
            try:
                cert = load_cert("Pasdaran.local.crt")
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                client_certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])
            except Exception as e:
                logging.error(f"Error handling client certificate: {str(e)}")
                raise e
        try:
            self.pre_master_secret = generate_pre_master_secret()

            # Encrypt pre-master secret with server's public key who extracted from server certificate
            self.encrypted_pre_master_secret = encrypt_pre_master_secret(self.pre_master_secret, self.server_public_key)
            
            if not isinstance(self.encrypted_pre_master_secret, bytes):
                self.encrypted_pre_master_secret = bytes(self.encrypted_pre_master_secret)


            # validate the length of the encrypted pre-master secret
            length_bytes = len(self.encrypted_pre_master_secret).to_bytes(2, 'big')

            # יצירת המבנה המלא של ClientKeyExchange
            client_key_exchange_data = length_bytes + self.encrypted_pre_master_secret

            client_key_exchange = TLSClientKeyExchange(
                exchkeys=client_key_exchange_data
            )
            self.tls_context.msg = [client_certificate, client_key_exchange] if client_certificate else [client_key_exchange]
            self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)

        except Exception as e:
            logging.error(f"Error in client key exchange: {str(e)}")
            raise e
```

#### Calculate Master Secret
```python
def handle_master_secret(self)-> None:
        # Before generating the master secret,
        # try to decrypt the pre-master secret with server's private key
        try:
            decrypted_pre_master_secret = decrypt_pre_master_secret(self.encrypted_pre_master_secret, self.server_private_key)
        except Exception as e:
            raise ValueError("Pre-master secret does not match") from e

        # Compute master secret
        self.master_secret = self.prf.compute_master_secret(
            self.pre_master_secret,
            self.client_random,
            self.server_random
        )
        print(f"Master secret: {self.master_secret.hex()}")
        # Derive key material
        key_block = self.prf.derive_key_block(
            self.master_secret,
            self.server_random,
            self.client_random,
            2 * (16 + 32 + 16)  # 2 * (key_length + mac_key_length + iv_length)
        )
        self.client_write_key = key_block[:16]
        self.server_write_key = key_block[16:32]
        self.client_write_mac_key = key_block[32:64]
        self.server_write_mac_key = key_block[64:96]
        self.client_write_IV = key_block[96:112]
        self.server_write_IV = key_block[112:128]
```

#### Client Change Cipher Spec
```python
def send_client_change_cipher_spec(self)-> None:
        client_verify_data = self.prf.compute_verify_data(
            'client',
            'write',
            b''.join(self.handshake_messages),
            self.master_secret
        )
        client_finished = TLSFinished(vdata=client_verify_data)
        """sent by both the client and the
            server to notify the receiving party that subsequent records will be
            protected under the newly negotiated CipherSpec and keys."""
        self.tls_context.msg = [TLSChangeCipherSpec()]
        self.tls_context.msg = [client_finished]
        self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)
```
Explain:

#### Server Change Cipher Spec packet
```python
def send_server_change_cipher_spec(self):
        # Server Finished
        server_verify_data = self.prf.compute_verify_data(
            'server',
            'write',
            b''.join(self.handshake_messages),
            self.master_secret
        )

        decrypted_pre_master_secret = decrypt_pre_master_secret(self.encrypted_pre_master_secret, self.server_private_key)
        
        logging.info(f"Server decrypted pre_master_secret: {decrypted_pre_master_secret.hex()}")

        finished = TLSFinished(vdata=server_verify_data)
        
        self.tls_context.msg = [TLSChangeCipherSpec()]
        self.tls_context.msg = [finished]
        self.send_tls_packet(self.server_ip, self.client_ip, self.server_port, self.client_port)
        logging.info(f"Server Finished sent to {self.client_ip}")
```

#### Create SSLKeyLog File
```python
def handle_ssl_key_log(self):
        try:
            # Log SSL key for Wireshark decryption
            log_line = f"CLIENT_RANDOM {self.client_random.hex()} {self.master_secret.hex()}"
            with open(self.pcap_writer.config.SSL_KEYLOG_FILE, "a") as f:
                f.write(log_line + "\n")
            logging.info(f"Logged master secret to {self.pcap_writer.config.SSL_KEYLOG_FILE}: {log_line}")
        except Exception as e:
            logging.error(f"Failed to derive master secret for decryption: {str(e)}")
            raise e
            
        # check if the SSLKEYLOG's master secret is correct
        if verify_master_secret(self.client_random, self.master_secret, self.pcap_writer.config.SSL_KEYLOG_FILE):
            logging.info(f"Derived master_secret: {self.master_secret.hex()}")
        else:
            raise Exception("Master secret verification failed")
```
#### Application Data Encryption
Code for encrypting and decrypting application data using AES-128-CBC with HMAC-SHA256.
```python
def send_application_data(self, data, is_request):
        is_client = is_request
        key = self.client_write_key if is_client else self.server_write_key
        mac_key = self.client_write_mac_key if is_client else self.server_write_mac_key
        
        iv = os.urandom(16)  # Generate a new IV for each message
        
        # Encrypt the data using CBC mode with HMAC-SHA256 for integrity
        encrypted_data = encrypt_tls12_record_cbc(data, key, iv, mac_key)
        self.encrypted_packets.append(encrypted_data)
        self.original_messages.append(data)
        
        # שמור את המפתח וה-IV
        self.packet_keys.append(key)
        self.packet_ivs.append(iv)
        self.packet_mac_keys.append(mac_key)
        
        # Create a TLS Application Data record
        tls_data = TLSApplicationData(data=encrypted_data)
        self.tls_context.msg = [tls_data]
        
        src_ip = self.client_ip if is_request else self.server_ip
        dst_ip = self.server_ip if is_request else self.client_ip
        sport = self.client_port if is_request else self.server_port
        dport = self.server_port if is_request else self.client_port
        
        # Send the encrypted TLS packet
        self.send_tls_packet(src_ip, dst_ip, sport, dport)
```
##### issue
An issue is noted with SSL keylog decryption in Wireshark, and potential reasons are explored.

- I looked on the Wireshark Open Source for understand how they are implement the decryption.
This trying worked a little bit......

- Checking a "real pcap" decryption procces and compare with my pcap, with TShark commands.
```bash
tshark -r <pcap_name.pcap> \
    -o "tls.keylog_file:<sslkeylog_name.log>" \
    -o "tls.debug_file:<tls_debug_name.txt>" \
    -V
```
The issue is not with: sslkeylog details, pre master secret, ............
מצאתי שתהליך הפענוח הוא כזה:
תחילה, נבדק XXX
אח"כ XXX
אח"כ XXX
לא אמורה להיות בעיה כאן כי...

- I though maby the issue is the fact I used Self Signed Certificate and no CA sigend for server, so OS not בוטחת in that. But this thing only for the 
- .
- .
- .

### Create Communication
```python

```

#### Server File
```python
def main():
    # Set up SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_OPTIONAL  # Allow optional client cert

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen(5)
    server_socket.settimeout(5)  # Set timeout for 5 seconds

    print("Server is up and running, waiting for a client...")

    # Start a thread to print the encryption key if no connection is made in 5 seconds
    if not print_encryption_key():
        server_socket.close()
        return

    try:
        client_socket, client_address = server_socket.accept()
        print(f"Client connected from {client_address}")

        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        # Check for client certificate
        cert = ssl_socket.getpeercert()
        if not cert:
            print("No client certificate provided.")
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n"
            response += "Hint: Use a self-signed certificate (Country: IL, CN: Pasdaran.local) to access the resource."
            ssl_socket.send(response.encode())
            ssl_socket.close()
            return

        # Handle client request
        data = ssl_socket.recv(protocol.MAX_MSG_LENGTH).decode()
        print(f"Client sent: {data}")
        
        response = handle_client_request(ssl_socket)
        ssl_socket.send(response.encode())

        ssl_socket.close()
    except socket.timeout:
        print("No client connected within 5 seconds. Server is stopping.")
    finally:
        server_socket.close()
```

#### Client no-cert File
```python
def main():
    # Initialize the socket
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    print(f"Connecting to {'127.0.0.1'}:{protocol.SERVER_PORT}")
    my_socket.connect(('127.0.0.1', protocol.SERVER_PORT))
    
    # Send a "Hello" message to the server
    message = "Hello"
    my_socket.send(message.encode())
    print(f"Sent: {message}")

    # Receive a response from the server
    response = my_socket.recv(1024).decode()
    print(f"Received: {response}")
    
    # Close the socket
    my_socket.close()
```

#### Client cert File
```python
def client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(('localhost', 443)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
            print(f"Connected to {secure_sock.getpeername()}")
            secure_sock.send(b"GET /resource HTTP/1.1\r\nHost: localhost\r\n\r\n")
            
            response = b""
            while True:
                chunk = secure_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            print(f"Received response of {len(response)} bytes")
```

#### Protocol File
```python
MAX_MSG_LENGTH = 1024
SERVER_PORT = 8110
SERVER_IP = "0.0.0.0"
ENCRYPTION_KEY = "RandomEncryptionKey123!@#"
```
## Analyzing Protocol Tools

used:
```bash
tshark -r <pcap_file> \
    -o"tls.keylog_file:<path_to_sslkeylog_file>" \
    -d "tcp.port==<port>,tls" \
    -Y "tls.app_data" \
    -T fields \
    -e tls.app_data
```
tshark -r new_output.pcap \
    -o "tls.keylog_file:sslkeylog_sniffEx.log" \
    -d "tcp.port==443,tls" \
    -Y "tls.app_data" -T fields \
    -e tls.app_data


```bash
tshark -r new_output.pcap \
    -o "tls.keylog_file:sslkeylog_sniffEx.log" \
    -o "tls.debug_file:tls_debug.txt" \
    -V
```

```bash
tshark -r output.pcap \
     -o "tls.keylog_file:sslkeylog_ctf.log" \
     -d "tcp.port==443,tls" \
     -o "tls.debug_file:tls_debug.txt" \
     -Y "tls && ip.src == 192.168.1.1" \
     -T fields \
     -e frame.number \
     -e tls.record.content_type \
     -e tls.handshake.type \
     -e tls.app_data
```
## Known Limitations

- **No Padding Support**: Ensure that your data length is a multiple of 16 bytes, as the algorithm processes data in 16-byte blocks. Padding is not supported.

## Contributing

Feel free to contribute to the project by opening issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
