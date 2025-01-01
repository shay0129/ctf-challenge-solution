# CTF Challenge: TLS Handshake and Encryption Algorithms

## **Introduction**
This repository contains a Capture The Flag (CTF) challenge that simulates vulnerabilities in TLS communication. Participants will analyze traffic, fix clients, and create secure communications using cryptography, reverse engineering, and network analysis tools.
![CTF Diagram](documents/ctf-diagram.png)

pip install -r requirements.txt

## Table of Contents
- [Challenge Description](#challenge-description)
- [Subjects](#subjects)
- [Usage](#usage)
    - [PCAP Creation Overview](#pcap-creation-overview)
        - [TLS Handshake Steps](#tls-handshake-steps)
        - [Client Hello](#client-hello)
        - [Server Hello](#server-hello)
        - [Client Key Exchange](#client-key-exchange)
        - [Calculate Master Secret](#calculate-master-secret)
        - [Client Change Cipher Spec](#client-change-cipher-spec)
        - [Server Change Cipher Spec](#server-change-cipher-spec)
        - [Create SSLKeyLog File](#create-sslkeylog-file)
            - [issue](#issue)
        - [Application Data Encryption](#application-data-encryption)
    - [SSL Communication Overview](#ssl-communication-overview)
        - [CA Server](#ca-server)
        - [CSR Client](#csr-client)
        - [Server](#server)
        - [Advanced Client Handle](#advanced-client-handle)
    - [External Services Overview](#external-services-overview)
        - [PE stole](#pe-stole)
- [Challenge Steps](#challenge-steps)
- [Participants Solution](#participants-solution)
- [External Tools](#external-tools)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

## Challenge Description

The challenge is themed around the Ritchie Boys, a historical group of German-born individuals recruited by the US Army in World War II for intelligence and psychological warfare against Nazi Germany.
In the context of the challenge, the Ritchie Boys Force is revived in 2025 to combat Iran's Islamic Revolutionary Guard Corps.
The player's goal is to compromise an Iranian server and extract the encryption key used for the organization's radio communications.

Here's the improved version of the **Subjects** section:

---

## Subjects
This challenge develops a broad range of technical skills, including:

1. **Network Traffic Analysis**:
   - Using Wireshark to analyze captured network packets.
   
2. **Python Scripting**:
   - Creating PCAP files with Scapy.
   - Implementing socket programming for communication emulation.

3. **Operating System Forensics**:
   - Analyzing PE file formats.
   - Applying forensic techniques for hidden data extraction.

4. **Cryptography**:
   - Understanding encryption key generation and usage.
   - Decrypting files and securing communication.

5. **HTTP Protocol Analysis**:
   - Identifying and exploiting bugs in HTTP communications.

6. **Reverse Engineering**:
   - Extracting and embedding executable files within PDFs.

7. **PCAP File Creation**:
   - Simulating network interactions and capturing them for analysis with Scapy.

8. **Protocol Analysis Tools**:
   - Leveraging TShark for deeper protocol inspection.
   - Using OpenSSL for TLS/SSL operations in a WSL environment.

---


## Usage


---

### **PCAP Creation Overview**
![PCAP Screenshot](documents/pcap_screenshot.png)

The **UnifiedTLSSession** class facilitates the simulation of a TLS session between a client and a server, enabling the creation of PCAP files.
Core Features:
1. **TLS Handshake**: Simulates certificate exchange and encryption negotiation to establish a secure connection.
2. **Application Data Exchange**: Supports both encrypted `TLS` and unencrypted `HTTP` communication based on session configuration.

```python
def main() -> None:

    # Load configuration first
    config = NetworkConfig.load()

    # Setup logging using the log_path and log_level from config
    setup_logging(
        log_path=config.log_path, 
        level=config.log_level
    )
    logging.info("Starting TLS session simulation")

    # Setup environment and continue with rest of the code
    writer = setup_environment(config)
    
    # Run Client 1 session (with certificate)
    run_client_session(
        writer=writer,
        client_ip=NetworkAddresses.CLIENT_1_IP,
        server_ip=NetworkAddresses.SERVER_IP,
        client_port=NetworkPorts.CLIENT_DEFAULT,
        use_client_cert=True,
        request=NetworkConfig.GET_REQUEST,
        response=NetworkConfig.OK_RESPONSE,
        challenge_file=CHALLENGE_FILE
    )
    
    # Run Client 2 session (without certificate)
    run_client_session(
        writer=writer,
        client_ip=NetworkAddresses.CLIENT_2_IP,
        server_ip=NetworkAddresses.SERVER_IP,
        client_port=NetworkPorts.CLIENT_DEFAULT + 1,
        use_client_cert=False,
        request=NetworkConfig.GET_REQUEST,
        response=NetworkConfig.BAD_REQUEST
    )
    
    # Save and verify results
    save_results(writer, config)
```
#### **Explanation**

1. **Client 1 Session:**
   - Initiates a secure TLS handshake with the server.
   - Sends a valid GET request and receives a response containing a GIF file (`ctf_challenge.gif`).

2. **Client 2 Session:**
   - Attempts to connect but does not provide a client certificate.
   - Receives a `400 Bad Request` response due to certificate verification failure.

3. **PCAP File Generation:**
   - The `writer.save_pcap` method writes the recorded packets to the specified file (`config.OUTPUT_PCAP`).
   - The `writer.verify_and_log_packets` method ensures the correctness of the generated PCAP and logs any discrepancies.

---
### TLS Handshake Steps
TLS Handshake Steps: Functions for each step of the TLS handshake, including ClientHello, ServerHello, key exchange, and setting up secure communication.
```python
def perform_handshake(self) -> bool:

        send_client_hello(self)
        send_server_hello(self)
        send_client_handshake_messages(self)
        handle_master_secret(self)
        """ה-ChangeCipherSpec אומר לצד השני "מעכשיו אני משתמש בהצפנה"
הודעת ה-Finished צריכה להיות מוצפנת עם המפתחות החדשים

ההודעה נועדה ליידע את הצד השני בשיחה (במקרה זה השרת) שמעתה כל ההודעות שישלחו יהיו מוצפנות וישתמשו במפתחות הסימטריים שנוצרו בשלב הקודם.

"""
        send_client_change_cipher_spec(self)
        send_server_change_cipher_spec(self)
        handle_ssl_key_log(self)
        
        self.state.handshake_completed = True
        logging.info("TLS Handshake completed successfully")
        return True
```
---
#### **Client Hello**
**Purpose**: The client Initiates the handshake by sending the supported `ciphers`, `extensions`, and `random` bytes.
```python
def create_client_hello(
    session,
    extensions: Optional[ClientExtensions] = None
    ) -> TLSClientHello:

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
```
 ***Explanation:***
1. **Client Random:** Combines the GMT Unix timestamp and 28 random bytes.
2. **Supported Ciphers:** Advertises the supported algorithms for encryption and hashing.
3. **Extensions:** Adds optional features like server name indication, supported groups, and signature algorithms.

---

#### **Server Hello**
**Purpose**: Responds to the `Client Hello` by  server `random` bytes`selected cipher` (encryption parameters) and `extenstions`.
```python
def create_server_hello(
        session,
        extensions: Optional[ServerExtensions] = None
        ) -> TLSServerHello:

    # Generate server random
    session.server_GMT_unix_time, session.server_random_bytes = generate_random()
    session.server_random = session.server_GMT_unix_time.to_bytes(4, 'big') + session.server_random_bytes
    logging.info(f"Generated server_random: {session.server_random.hex()}")

    # Use default extensions if none provided
    if not extensions:
        extensions = ServerExtensions(
            signature_algorithms=['sha256+rsaepss']
        )

    return TLSServerHello(
        version=TLSVersion.TLS_1_2,
        gmt_unix_time=session.server_GMT_unix_time,
        random_bytes=session.server_random_bytes,
        sid=os.urandom(32),
        cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val,
        ext=extensions.get_extension_list()
    )
```
 ***Explanation:***
1. **Server Random:** Combines a timestamp and random bytes for key generation.
2. **Selected Cipher:** Agrees upon one cipher suite from the client’s list.
3. **Extensions:** Adds advanced security options like extended master secrets.

![server certificate signed by ca](documents/signed_server_cert.png)
---

#### Client Key Exchange
**Purpose**: The client generates a `Pre-Master Secret`, encrypts it, and sends it to the server.
This secret is encrypted using the server's `public key`, making it accessible only to the intended recipient.
```python
def create_client_certificate_and_key_exchange(
        session
        ) -> tuple[TLSCertificate, TLSClientKeyExchange]:

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
```
 ***Explanation:***
1. **Client Certificate:** A TLS certificate representing the client is prepared and appended to the handshake messages.
2. **Pre-Master Secret:** A randomly generated `pre-master secret` is created for the session.
This value serves as the foundation for deriving the `master secret` used in subsequent encryption.
3. **Encryption:** The `pre-master secret` is encrypted using the `server's public key`, ensuring secure transmission.
The encryption guarantees that only the server, possessing the corresponding `private key`, can decrypt it.
4. **Key Exchange Message:** The encrypted `pre-master secret` is packaged into a key exchange message, preceded by its length in bytes.

Notice:
ב-TLS 1.2, כאשר משתמשים ב-RSA Key Exchange, לא נשלחת הודעת ServerKeyExchange.
תהליך ה-Handshake מבוסס על הצפנה של Pre-Master Secret עם המפתח הציבורי של השרת, ולכן אין צורך בחתימה נוספת מצד השרת כדי לוודא את הזהות שלו.
לעומת זאת, במקרים של Diffie-Hellman (DH) או Elliptic Curve Diffie-Hellman (ECDH), כן נדרשת הודעת ServerKeyExchange.

```python
def generate_master_secret(
        session,
        encrypted_pre_master_secret: bytes,
        client_random: bytes,
        server_random: bytes
    ) -> bytes:

    # Decrypt pre-master secret
    pre_master_secret = decrypt_pre_master_secret(
        encrypted_pre_master_secret,
        session.server_private_key
    )
    
    logging.info(
        f"Decrypted pre_master_secret: {pre_master_secret.hex()}"
    )
    
    # Compute master secret
    master_secret = session.prf.compute_master_secret(
        pre_master_secret,
        client_random,
        server_random
    )
    
    logging.info(f"Generated master secret: {master_secret.hex()}")
    return master_secret
```
The `encrypt_pre_master_secret()` function:
- PKCS1v15 padding (standard for RSA encryption)
- Encrypts the pre-master secret with the server's public key
- Returns the encrypted bytes
---

#### Calculate Master Secret
**Purpose:** The `master secret` is a crucial part of the TLS handshake, derived by both the client and server using the `pre-master secret` and `random` values exchanged during the handshake. It ensures the secure generation of session keys for encryption and integrity checks.


```python
def handle_master_secret(session) -> None:

    session.master_secret = generate_master_secret(
        session,
        session.encrypted_pre_master_secret,
        session.client_random,
        session.server_random
    )

```
 ***Explanation:***
1. **Client Side:**
   - The client encrypts the `pre_master_secret` using the server's public key from its certificate.
   - This ensures that only the server can decrypt it.

2. **Server Side:**
   - The server decrypts the `pre_master_secret` using its private key.
   - This step verifies that the client has a valid server certificate and ensures confidentiality.

3. **Both Sides:**
   - Using the same `pre_master_secret`, along with the `client_random` and `server_random`, both the client and server derive the same `master_secret`.
   - This `master_secret` is the foundation for symmetric encryption keys used in the session.

---

#### Client Change Cipher Spec

**Purpose:** The `ChangeCipherSpec` message is sent by the client to notify the server that it will start using the negotiated encryption and MAC settings. This is immediately followed by the `Finished` message, encrypted with the newly established settings.

```python
def send_client_change_cipher_spec(session) -> bytes:

    # Create messages
    client_finished, change_cipher_spec = create_client_finished(session)

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

```
 ***Explanation:***
1. **Verify Data:**
   - The client computes the `verify_data` using all previous handshake messages and the derived `master_secret`.
   - This ensures the integrity of the handshake.

2. **ChangeCipherSpec Message:**
   - Signals the server that future messages will use the negotiated encryption and integrity settings.

3. **Finished Message:**
   - This is the first message encrypted with the new cipher settings, proving that both client and server share the same session keys.

---
#### Server Change Cipher Spec
- **Purpose:** The server sends the `ChangeCipherSpec` message to notify the client it will use the negotiated encryption settings. It follows with the `Finished` message, encrypted with the new settings, to confirm the handshake.

```python
def send_server_change_cipher_spec(session) -> bytes:

    # Create messages
    server_finished, change_cipher_spec = create_server_finished(session)

    # Send messages
    session.send_to_client(server_finished)
    session.send_to_client(change_cipher_spec)

    # Update handshake state
    session.handshake_messages.append(raw(server_finished))
    session.handshake_messages.append(raw(change_cipher_spec))
    session.tls_context.msg = [change_cipher_spec, server_finished]

    logging.info("Server ChangeCipherSpec and Finished messages sent")
    return session.send_tls_packet(
        session.server_ip,
        session.client_ip,
        session.server_port,
        session.client_port,
        is_handshake=True
    )
```
 ***Explanation:***
1. **Verify Data:**
   - The server computes `verify_data` using the handshake messages and `master_secret`.
   - Confirms the integrity and authenticity of the handshake.

2. **ChangeCipherSpec Message:**
   - Notifies the client that the server is switching to the negotiated encryption settings.

3. **Finished Message:**
   - Sent encrypted, verifying that the server is ready for secure communication.

Here’s the revised section in the desired format:

---

#### **Create SSLKeyLog File**

- **Purpose:** Enables debugging of encrypted TLS traffic by exporting the `master_secret` and `client_random` to a log file, making it compatible with tools like Wireshark.  

```python
def setup_environment(config: NetworkConfig) -> CustomPcapWriter:

    writer = CustomPcapWriter(config)
    
    # Clear SSL keylog file
    if hasattr(config, 'SSL_KEYLOG_FILE'):
        Path(LoggingPaths.SSL_KEYLOG).write_text('')
        logging.info(f"Cleared SSL keylog file: {LoggingPaths.SSL_KEYLOG}")
        
    return writer

def handle_ssl_key_log(session) -> None:

    # Make sure directory exists
    LoggingPaths.SSL_KEYLOG.parent.mkdir(parents=True, exist_ok=True)
    
    # Open in write mode to clear previous content
    with open(LoggingPaths.SSL_KEYLOG, "w") as f:
        client_random_hex = session.client_random.hex()
        master_secret_hex = session.master_secret.hex()
        # Format: CLIENT_RANDOM <client_random_hex> <master_secret_hex>
        f.write(f"CLIENT_RANDOM {client_random_hex} {master_secret_hex}\n")
```

***Explanation:***  
1. **Clearing the SSL Key Log File:**  
   - The log file is cleared at the start to ensure no residual data from previous sessions interferes with debugging.  

2. **Writing Keys:**  
   - The `client_random` and `master_secret` are logged in the format:  
     ```
     CLIENT_RANDOM <client_random> <master_secret>
     ```  
   - This allows Wireshark to decrypt the captured traffic by reconstructing session keys.  

3. **Integration with Wireshark:**  
   - The generated log file can be loaded into Wireshark via the *SSL protocol settings* to enable real-time decryption of the TLS packets.  

גזירת ה-master secret  כוללת שימוש בנתונים אקראיים (nonces) שנוצרו על ידי הלקוח והשרת. זה מונע שימוש חוזר ב-master secret  ב sessions שונים, גם אם ה-pre-master secret  נשאר זהה.
בקובץ זה קיים session יחיד לכל לקוח.
אילו היו עוד sessions לכל לקוח, היו מספר של master secret לכל לקוח.

---

### **Notice: SSL Key Log File Decryption Issue**

#### **Context**
The `SSL_KEYLOG_FILE` functionality was implemented to allow decryption of encrypted TLS traffic in tools like Wireshark and TShark. However, during testing, I encountered difficulties in successfully decrypting the `Application Data` packets in both Wireshark and TShark.

#### **Steps Taken to Address the Issue**

ערכתי קובץ PCAP אמיתי, וחילצתי ממנו tls stream אחד, כדי לבצע בדיקה מצומצמת.
```bash
tshark -r TLSsniffEx.pcapng \
    -Y "(ip.dst == 193.34.188.81 or ip.src == 193.34.188.81) and frame.number > 65 and frame.number < 96" \
     -w miniTLSsniffEx.pcap
```

ביצוע debug על הPCAPs:
```bash
tshark -r miniTLSsniffEx.pcap \
    -o "tls.keylog_file:sslkeylog_sniffEx.log" \
    -o "tls.debug_file:debug_sniffEx.txt" \
    -V > output_sniffEx.txt


tshark -r capture.pcap \
    -o "tls.keylog_file:ssl_key_log.log" \
    -o "tls.debug_file:debug_capture.txt" \
    -V > output_capture.txt
```

מסקנות:
אני רואה כמה נקודות חשובות בדיבאג:

1. **בעיית הPre-Master Secret**:
```
ssl_decrypt_pre_master_secret: decryption failed: -49 (No certificate was found.)
ssl_generate_pre_master_secret: can't decrypt pre-master secret
```
Wireshark לא מצליח לפענח את ה-pre-master secret למרות שיש לנו מפתח תקין ב-SSLKEYLOG. זה יכול להיות קשור לאיך שהמפתח מיוצא.

2. **בעיית Master Secret**:
למרות שאנחנו מצליחים לקרוא את ה-master secret מה-SSLKEYLOG:
```
Client Random[32]:
| 67 74 3f 23 fc 15 af ab 81 15 dd 81 72 3e a2 bd |
...
(pre-)master secret[48]:
| 1e 08 9f 36 9f 9b 76 8c 0c 05 b5 73 03 8b 5e 39 |
```

יש בעיה בשימוש בו:
```
ssl_restore_master_key can't find master secret by Session ID
ssl_restore_master_key can't find master secret by Client Random
Cannot find master secret
```

3. **בעיית Key Block**:
```python
key_block = session.prf.derive_key_block(
    session.master_secret,
    b"key expansion",
    session.server_random + session.client_random,
    key_length
)
```
אנחנו מייצרים את ה-key block נכון, אבל Wireshark לא משתמש במפתחות האלה.

זה נראה שיש בעיה במעבר בין השלבים:
1. יצירת ה-pre master secret
2. גזירת ה-master secret
3. יצירת מפתחות ההצפנה
4. שימוש במפתחות להצפנה

אולי נבדוק:
1. האם ה-SSLKEYLOG מכיל את ה-master secret הנכון (לבדוק hash של המפתח)
2. האם סדר הbytes של ה-client_random ו-master_secret בקובץ SSLKEYLOG נכון
3. האם הפורמט של קובץ הLOG תואם בדיוק למה שWireshark מצפה

מה דעתך?


יצירת ה-pre master secret
utils/crypto.py
```python
def generate_pre_master_secret() -> bytes:
    tls_version_bytes = TLSVersion.TLS_1_2.to_bytes(2, byteorder='big')
    random_bytes = secrets.token_bytes(46)
    pre_master_secret = tls_version_bytes + random_bytes
```
גזירת ה-master secret
```python
def generate_master_secret(session, encrypted_pre_master_secret, client_random, server_random):
    pre_master_secret = decrypt_pre_master_secret(
        encrypted_pre_master_secret,
        session.server_private_key
    )
    
    master_secret = session.prf.compute_master_secret(
        pre_master_secret,
        client_random,
        server_random
    )
```
שימוש בו
```python
def create_client_certificate_and_key_exchange(...):
# Generate and encrypt pre-master secret
session.pre_master_secret = generate_pre_master_secret()
session.encrypted_pre_master_secret = encrypt_pre_master_secret(
    session.pre_master_secret,
    session.server_public_key
)
```
נראה תקין - אנחנו מפענחים את ה-pre_master_secret ומשתמשים בו עם ה-PRF ליצירת ה-master_secret.


יצירת מפתחות ההצפנה
שימוש במפתחות להצפנה


#### Application Data Encryption
Code for encrypting application data using AES-128-CBC with HMAC-SHA256.
```python
def _handle_encrypted_exchange(
        self,
        request_data: bytes,
        response_data: bytes,
        file_to_send: Optional[str]
    ) -> None:
        """Handle encrypted data exchange"""
        try:
            # Send client request
            logging.info("Sending encrypted request data")
            encrypt_and_send_application_data(
                self, request_data, is_request=True,
                prf=self.prf, master_secret=self.master_secret,
                server_random=self.server_random, client_random=self.client_random,
                client_ip=self.client_ip, server_ip=self.server_ip,
                client_port=self.client_port, server_port=self.server_port,
                tls_context=self.tls_context, state=self.state
            )
            
            # Send server response
            logging.info("Sending encrypted response data")
            encrypt_and_send_application_data(
                self, response_data, is_request=False,
                prf=self.prf, master_secret=self.master_secret,
                server_random=self.server_random, client_random=self.client_random,
                client_ip=self.client_ip, server_ip=self.server_ip,
                client_port=self.client_port, server_port=self.server_port,
                tls_context=self.tls_context, state=self.state
            )
            
            # Send file if available
            if file_to_send:
                logging.info(f"Attempting to send file: {file_to_send}")
                self._send_file(file_to_send)
                logging.info("File sent successfully")
                    
```
issue in encoding procces:
נראה שהבעיה היא קצת יותר עמוקה. בוא נסתכל על החבילות המוצפנות:

1. **יצירת ה-Decoder ב-Wireshark**:
```
ssl_generate_keyring_material ssl_create_decoder(client)
decoder initialized (digest len 32)
ssl_generate_keyring_material ssl_create_decoder(server)
decoder initialized (digest len 32)
```
Wireshark מצליח ליצור את ה-decoders.

2. **אבל בפענוח**:
```
decrypt_ssl3_record: using client decoder
decrypt_ssl3_record: no decoder available
```
הוא מחליט שאין decoder זמין.

הבעיה יכולה להיות:
1. או בחיבור בין ה-`ChangeCipherSpec` ל-key block
2. או במבנה של החביל


### SSL Communication Overview
שרת CA ולקוח.
שרת רגיל ולקוח.

הלקוח תחילה מבקש מCA שיחתום לו על client csr.
הCA חותם ושולח בחזרה crt file חתום.

#### Server Implementation
Translate to English: השרת מתוכן לבצע TLS Handshake, ומצפה לקבל Client Certificate מהלקוח שמתקשר עמו.
אם לקוח לא הטעין Client Certificate, אז הוא פועל באופן הבא:
שולח encrypted response עם השגיאה שקרתה.
שולח 400 bad request.

```python
def server():
    global running
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_OPTIONAL  # Allow optional client cert
    context.check_hostname = False
    context.verify_flags = ssl.VERIFY_DEFAULT | ssl.VERIFY_X509_TRUSTED_FIRST
    context.load_verify_locations(cafile="client.crt")  # Trust the client's self-signed cert

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen(5)
    server_socket.setblocking(False)  # Set socket to non-blocking mode

    print(f"Server is up and running, waiting for a client on port {protocol.SERVER_PORT}...")
    print("Press Ctrl+C to stop the server.")

    start_time = time.time()
    key_printed = False

    # Set up the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while running:
            # Use select to wait for a connection with a short timeout
            ready, _, _ = select.select([server_socket], [], [], 0.1)
            
            if ready:
                client_socket, client_address = server_socket.accept()
                print(f"Client connected from {client_address}")

                try:
                    ssl_socket = context.wrap_socket(client_socket, server_side=True)
                    print("SSL handshake successful")
                    print(f"Using cipher: {ssl_socket.cipher()}")
                    print(f"SSL version: {ssl_socket.version()}")
                    
                    if handle_client_request(ssl_socket):
                        print("Client request handled successfully")
                    else:
                        print("Failed to handle client request")
                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")
                finally:
                    ssl_socket.close()
                    print("Connection closed")
            else:
                # No connection within the timeout period
                if not key_printed and time.time() - start_time > 5:
                    print_encryption_key()
                    key_printed = True
                print("Waiting for a new connection...", end='\r')
    
    finally:
        print("\nClosing server socket...")
        server_socket.close()
        print("Server has been shut down.")
```

#### Basic Client Handle

![Communication between server and client1](documents/communication-client1.png)
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

Translate to English:
מוריד קובץ למחשב של המשתתף במיקום קבוע מראש (C:\Users\<user_name>).
לאחר תום ה30 שניות, הקובץ נמחק מהתיקייה.

---

#### Advanced Client Handle
![Communication between server and client2](documents/communication-client2.png)
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
הלקוח המתקדם, שולח לשרת Client Certificate שחתום ע"י הCA שהשרת סומך עליו.

Issue:
the problem with sslkeylog.
tshark command for debugging:

```bash
tshark
-r capture.pcap
-o tls.keylog_file:SSLKEYLOG.log
-V
```

### External Services Overview

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

## Challenge Steps


## אתגר CTF: חדירה לרשת מאובטחת

**תיאור:**

אתגר זה ידרוש ממך לחדור לרשת מאובטחת על ידי ניצול חולשות בפרוטוקול TLS ופתרון צופן אניגמה. 

**צעדים:**

1. **ניתוח ראשוני:**
    * תקבל קובץ PDF עם תיאור המשימה וקובץ PCAP המכיל תעבורה רשת מוצפנת.
    * בתוך קובץ ה-PCAP, תמצא שני קבצים: `server.exe` ו- `client.exe`.
    * באמצעות ניתוח נוסף, תגלה שני קבצים נוספים: `ca_server.exe` ו- `csr_client.exe`.

2. **זיהוי החולשה:**
    * תגלה שהשרת (`server.exe`)  מאפשר חיבור רק ללקוחות עם תעודה דיגיטלית חתומה על ידי רשות אישורים ספציפית (`ca_server.exe`).
    * תנסה להתחבר לשרת עם `client.exe` ותגלה שהשרת דוחה את החיבור כי שם התחום (Common Name) בתעודה  שונה ממה שהוא מצפה.

3. **ניצול החולשה:**
    * תבין שלא ניתן לשנות את התעודה הדיגיטלית (`client.crt`) שקיבלת כי היא חתומה דיגיטלית.
    * תבצע  Man-in-the-Middle  (MITM) על התקשורת בין `csr_client.exe` (שמבקש תעודה) לבין `ca_server.exe` (רשות האישורים).
    * תשתמש ב- Burp Suite כדי ליירט ולשנות את בקשת התעודה (CSR)  ולזייף את שם התחום לערך הצפוי על ידי השרת.
    * רשות האישורים תחתום על הבקשה המזויפת ותנפיק תעודה דיגיטלית חדשה עם שם התחום הנכון.

4. **פענוח הצופן:**
    * תריץ את `client.exe` עם התעודה החדשה ותקבל קובץ תמונה מהשרת.
    * בתוך התמונה, תמצא רמז לצופן אניגמה.
    * במקביל, תבחין שהשרת שולח הודעות מוצפנות באמצעות אניגמה.
    * תחקור את צופן האניגמה ותשתמש בכלים זמינים כדי לפענח את ההודעות.

5. **השגת הדגל:**
    * תפענח את התעבורה המוצפנת ב- PCAP.
    * תמצא את ה- `client random` וה- `master secret` מהודעות האניגמה ותשתמש בהם כדי לפענח את תעבורת ה- TLS ב- Wireshark.
    * תמצא את הדגל  שנשלח מהשרת ללקוח בתוך התעבורה המפוענחת.

**רמזים:**

* חקור את פרוטוקול TLS ואת אופן פעולתו של צופן אניגמה.
* השתמש בכלים כמו Burp Suite ו- Wireshark לניתוח תעבורה רשת.
* חפש מידע באינטרנט על  MITM וזיוף תעודות דיגיטליות.

**בהצלחה!**

---

## Participants Solution

בחלק זה של ה-README, הייתי מתאר את הפתרונות האפשריים לאתגר, תוך התמקדות בדרכים בהן משתתפים עשויים לגשת לבעיה ולפתור אותה. הנה דוגמה לניסוח אפשרי:

**פתרונות אפשריים:**

* **זיהוי חולשת MITM:** משתתפים מנוסים יזהו את הפוטנציאל לביצוע מתקפת MITM על התקשורת בין הלקוח לרשות האישורים. הם יבינו שזיוף בקשת התעודה (CSR) יאפשר להם לקבל תעודה דיגיטלית עם שם התחום הנכון, ובכך לעקוף את בדיקת השרת.
* **שימוש ב- Burp Suite:** משתתפים יוכלו להשתמש ב- Burp Suite או בכלי פרוקסי אחר כדי ליירט ולשנות את תעבורת הרשת בין `csr_client.exe` ל- `ca_server.exe`.  
* **זיוף שם התחום:**  המשתתפים יצטרכו לזהות את שם התחום הצפוי על ידי השרת ולשנות את ה- CSR בהתאם.
* **פענוח צופן אניגמה:** לאחר התחברות מוצלחת לשרת, המשתתפים יצטרכו לנתח את קובץ התמונה והודעות השרת כדי להבין שמדובר בצופן אניגמה.  הם יוכלו להשתמש בכלים מקוונים או לכתוב סקריפטים לפענוח הצופן.
* **חילוץ מידע מהודעות אניגמה:** המשתתפים יצטרכו לזהות ולהשתמש במידע חיוני מהודעות האניגמה המפוענחות, כמו  `client random` ו- `master secret`, כדי לפענח את תעבורת ה- TLS.
* **פענוח תעבורת TLS:**  המשתתפים יוכלו להשתמש ב- Wireshark או בכלי אחר לפענוח תעבורה רשת,  תוך שימוש במידע שחולץ מהודעות האניגמה.
* **מציאת הדגל:**  לבסוף, המשתתפים יצטרכו לנתח את התעבורה המפוענחת ולמצוא את הדגל.

**גיוונים אפשריים:**

* ייתכן שיהיו מספר דרכים לזייף את ה- CSR. 
* ייתכן שיהיו רמזים נוספים או אתגרים נסתרים בתוך קובץ התמונה או בהודעות האניגמה.
* ייתכן שיהיה צורך לבצע ניתוח מעמיק יותר של פרוטוקול TLS או של צופן אניגמה.

חשוב לציין שזהו רק תיאור כללי של פתרונות אפשריים.  המשתתפים עשויים למצוא דרכים יצירתיות וייחודיות לפתור את האתגר. 

מתחיל ספירה לאחור של 30 שניות, בהם המשתתף צריך לגלות את מיקום הקובץ בעזרת התוכנה שנרמזה לו מראש בהוראות לCTF, בשם procmon.
להלן תוצאות חיפוש בprocmon שבו רואים שהקובץ server.exe משתמש בהרשאת כתיבה לתיקייה C:\Users\ShayMordechai:
![procmon results](documents/from_procmon.png)


![burp setting](image.png)




ביצעתי את הפעולות הבאות:
הפעלתי את advanced_client מול server.
זיהיתי שהשרת משתמש במפתח ותעודת לקוח החתומה ע"י CA.
הפעלתי את מנגנון ההחתמה על תעודה.
גיליתי שתעודת הלקוח מכילה את הCN הלא רצוי מהserver.
לכן הפעלתי את burp וערכתי את הCSR שיהיה עם הCN המתאים.
שלחתי בburp את החבילה שערכתי עם CSR חדש.
קיבלתי חותמת של הCA server על הCSR החדש.

```bash
smordeha@DESKTOP-K3JHE4M:~$ openssl x509 -in client.crt -noout -text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            fc:89:52:3f:7c:87:32:8b
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C = IR, ST = Tehran, L = Tehran, O = IRGC, OU = Cybersecurity, CN = IRGC Root CA
        Validity
            Not Before: Dec 18 20:34:48 2024 GMT
            Not After : Dec 18 20:34:48 2025 GMT
        Subject: C = IL, ST = Tel Aviv, L = Tel Aviv, O = CyberSecurity, OU = IT, CN = ISRAEL
```
מכשול:
בכל הרצה, נוצר client.key שונה, לכן יש להשתמש במפתח המעודכן כדי ליצור CSR מותאם אישית.
במקרה והשתמשנו במפתח מההרצאה הקודמת, תתרחש חוסר התאמה בין המפתח הפרטי לבין תעודת הלקוח.
להלן בדיקה באמצעות MD5 hash כדי לבדוק האם המפתח הציבורי שבcrt מתאים למפתח הפרטי של הלקוח.
```bash
smordeha@DESKTOP-K3JHE4M:~$ openssl rsa -noout -modulus -in client.key | openssl md5
MD5(stdin)= ad4c091ef758454e202de341c289b1fa

smordeha@DESKTOP-K3JHE4M:~$ openssl x509 -noout -modulus -in client.crt | openssl md5
MD5(stdin)= 955d87e5c655aff32c33c3805d232f41
```

מקרה תקין:
```bash
smordeha@DESKTOP-K3JHE4M:/mnt/c/my-CTF/communication$ openssl x509 -noout -modulus -in client.crt | openssl md5
MD5(stdin)= 7ae4ac4e04f8900c088000ea94bac255
smordeha@DESKTOP-K3JHE4M:/mnt/c/my-CTF/communication$ openssl rsa -noout -modulus -in client.key | openssl md5
MD5(stdin)= 7ae4ac4e04f8900c088000ea94bac255
```

דוגמא לפקודה ליצירת CSR על סמך KEY קיים:
```bash
openssl req -new
-key client.key
-out israel.csr
-subj "/C=IL/ST=Tel Aviv/L=Tel Aviv/O=CyberSecurity/OU=IT/CN=ISRAEL"
```

.......



חזרתי ללקוח, והפעלתי אותו מול השרת שוב פעם.
כעת, השרת התרצה ושלח ללקוח קובץ נוסף:


## הנחיות למשתתף (ליצירת תעודת לקוח)
הנה המדריך למערכת האישורים:

1. הכנת ה-CA:
```bash
# יצירת מפתח CA
openssl genrsa -out guards.key 2048

# יצירת תעודת CA
openssl req -x509 -new -nodes -key guards.key -sha256 -days 3650 -out guards.crt \
-subj "/CN=CTF CA/C=IL"
```

2. קוד השרת יטען את ה-CA:
```python
context.load_verify_locations(cafile="guards.crt")
```

3. הוראות למשתתפים:
```bash
# יצירת מפתח פרטי
openssl genrsa -out client.key 2048

# יצירת בקשת חתימה (CSR)
openssl req -new -key client.key -out client.csr \
-subj "/CN=Pasdaran.local/C=IL"

# חתימת התעודה עם ה-CA
openssl x509 -req -in client.csr -CA guards.crt -CAkey guards.key \
-CAcreateserial -out client.crt -days 365
```

כך המשתתפים יוכלו ליצור תעודות חתומות על ידי ה-CA שלך.

סדר הפעולות:

לקוח שולח client.crt לשרת
שרת בודק אם התעודה חתומה על ידי ca.crt שהוא מכיר
אם כן, השרת בודק את התכונות של התעודה ב-verify_client_cert


# Install pyinstaller:
pip install pyinstaller

# Create EXEs:
pyinstaller --onefile server.py
pyinstaller --onefile basic_client.py

## External Tools

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


Create Signed Self Certificate:
create private key
```bash
openssl genpkey \
-algorithm RSA \
-out server.key \
-pkeyopt rsa_keygen_bits:2048
```
יצירת CA
```bash
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 \
    -days 3650 \
    -out ca.crt \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=IRGC/OU=Cybersecurity/CN=IRGC Root CA"
```

create csr:
```bash
openssl req \
-new -key server.key \
-out server.csr \
-subj "/C=IR/ST=Tehran/L=Tehran/O=Pasdaran/OU=Security/CN=www.ctf-example.org"
```
חתימה ע"י OpenSSL
```bash
openssl x509 \
-req -in server.csr \
-CA ca.crt \
-CAkey ca.key \
-CAcreateserial \
-out server.crt \
-days 365 \
-sha256
```
המרה לder
```bash
openssl x509 \
-req -days 365 \
-in server.csr \
-signkey server.key \
-out server.crt
```
extrach public key:
```bash
openssl rsa \
-in server.key \
-pubout \
-out server.pub
```
- **No Padding Support**: Ensure that your data length is a multiple of 16 bytes, as the algorithm processes data in 16-byte blocks. Padding is not supported.

## Contributing

Feel free to contribute to the project by opening issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# TLS Project

## Installation
```bash
pip install -e .
```
Usage:
```bash
python -m tls.main
```

3. כעת המרצה יוכל:
- להוריד את הקוד מהגיט
- להריץ `pip install -e .`
- ואז להריץ `python -m tls.main`

זו הדרך המקובלת לארגן פרויקטי Python, והיא תעבוד באופן עקבי בכל סביבה.

האם תרצה שאעזור לך להוסיף את התלויות הנדרשות ל-setup.py?