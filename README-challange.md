# my CTF challange

This repository provides a simple implementation of ...
![alt text](pcap-image.png)
## Table of Contents

- [Frame story](#frame-story)
- [Subjects](#subjects)
- [Characterization](#characterization)
- [Usage](#usage)
  - [Create PCAP File](#create-pcap-file)
    - [Create TLS Handshake](#create-tls-handshake)
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

## Frame story


In 1939, the US Army recruited about 10,000 German boys, mostly Jews, to defeat Nazi Germany in World War II.

In the year 2025, the Richie Boys Force has been re-established with a similar goal, to subdue Iran's Islamic Revolutionary Guard Corps.
You have been recruited into the Ritchie Boys cyber team, your job is to take over an Iranian server and find the encryption key used by the organization's radios.
The task will not be easy, but remember that the future of the world depends on you.

To help you with the task, the file of communication with Iranian servers has been attached.

successfully!

## Subjects

1. Wireshark: Understanding how to read and analyze network traffic.
2. Python programming: writing scripts for decoding and encryption.
3. Knowledge of operating systems: understanding of the PE format.
4. Cryptography: use of encryption keys and file decryption.
5. HTTP protocol: understanding of the protocol and ability to analyze bugs in it.
6. Reversing: using tools like IDA to analyze and understand binary code.//embedding an exe in a pdf file.
7. Creating the PCAP using the SCAPY library of PYTHON
8. כלי ניתוח פרוטוקולים: tshark, openssl בסביבת wsl.

## Characterization

1. Revealing the files: Participants receive the mission.pdf file. They must discover that the file contains hidden files (steganography) and extract server.exe and client.exe. They find that server.exe is a valid executable, but client.exe appears to be corrupted.
2. Client fix: Running server.exe alone prints a message with a random sequence of characters. An in-depth analysis of the message and understanding the relationship between it and client.exe reveals that it is used as an encryption key. Participants write a Python script that uses the key to decrypt client.exe and make it a valid executable file.
3. Communication analysis: The participants run server.exe and client.exe at the same time, but find that the client does not receive any information from the server. Analysis of the capture file (capture.pcapng) attached to mission.pdf reveals the bug in the server: it sends the response "200 OK" to the correct client, but it sends the requested resource to another client that does not exist.
4. Creating another client: To get around the bug, the participants understand that they must create another client (client2.exe or any other name) that will connect to the server at the same time as the original client. The new client needs to be different from the original so that the server does not identify it as a duplicate.
The difference between the clients is that the first does not load a certificate (therefore the resource does not reach it), the second does.
5. After connecting to the server 2 clients: the participants encounter another problem. The server requires client2 to load a self-signed certificate in order for it to send the resource to it.
The participants are asked to learn by themselves how to create a self-signed ssl certificate of this type (no need for a CA certificate), load it with a code that connects to the server, so that the server recognizes the certificate during the handshake, and sends it the requested resource.
For this, they must first create a localhost domain in the operating system.
If they loaded in crt format, they will receive a message that they must load der format.
6. Capturing the resource: The new client manages to get the correct resource sent from the server. The resource is an image file (resource.png) containing the flag in a visible form. Participants need to identify the flag and submit it to complete the challenge.
## Usage

### Create PCAP file
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

### Create TLS Handshake
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
For now, not succeded to decrypt the pcap with sslkeylog and wireshark.
After analyse that issue, my foundation:
- Checking a "real pcap" decryption procces and compare with my pcap.
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
- ....
- .
- .

### Create Communication
```python

```

#### Server File
```python

```

#### Client no-cert File
```python

```

#### Client cert File
```python

```

#### Protocol File
```python

```
## Analyzing

used:
```bash
tshark -r <pcap_file> -o "tls.keylog_file:<path_to_sslkeylog_file>" -d "tcp.port==<port>,tls" -Y "tls.app_data" -T fields -e tls.app_data
```
tshark -r new_output.pcap \
    -o "tls.keylog_file:sslkeylog_sniffEx.log" \
    -d "tcp.port==443,tls" \
    -Y "tls.app_data" -T fields \
    -e tls.app_data



tshark -r new_output.pcap \
    -o "tls.keylog_file:sslkeylog_sniffEx.log" \
    -o "tls.debug_file:tls_debug.txt" \
    -V


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

## Known Limitations

- **No Padding Support**: Ensure that your data length is a multiple of 16 bytes, as the algorithm processes data in 16-byte blocks. Padding is not supported.

## Contributing

Feel free to contribute to the project by opening issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.