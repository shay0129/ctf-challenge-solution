# my CTF challange

This repository provides a simple implementation of AES-128-CBC encryption and decryption in C using the `AES_128_CBC.h` header file. AES-128-CBC is a widely used symmetric encryption algorithm that operates on fixed-size blocks of data.

## Table of Contents

- [Frame story](#frame-story)
- [Characterization](#characterization)
- [Usage](#usage)
  - [Single Block Example](#single-block-example)
  - [Multiple Blocks Example](#multiple-blocks-example)
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

## characterization

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

### Single Block Example

```c
///
}
```

### Multiple Blocks Example

```c
/
```

## Building and Integration

This implementation is header-only, making it easy to integrate into your projects. Simply include the `AES_128_CBC.h` header file in your source code and link against the necessary libraries.

## Known Limitations

- **No Padding Support**: Ensure that your data length is a multiple of 16 bytes, as the algorithm processes data in 16-byte blocks. Padding is not supported.

## Contributing

Feel free to contribute to the project by opening issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
