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

- Simple AES-128-CBC encryption and decryption.
- Header-only implementation for easy integration.

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
