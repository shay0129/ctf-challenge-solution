# my CTF challange

This repository provides a simple implementation of AES-128-CBC encryption and decryption in C using the `AES_128_CBC.h` header file. AES-128-CBC is a widely used symmetric encryption algorithm that operates on fixed-size blocks of data.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Usage](#usage)
  - [Single Block Example](#single-block-example)
  - [Multiple Blocks Example](#multiple-blocks-example)
- [Building and Integration](#building-and-integration)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

## Introduction

AES-128-CBC operates on 128-bit blocks and supports key sizes of 128 bits. Cipher Block Chaining (CBC) mode introduces an Initialization Vector (IV) to each block, making each encryption operation dependent on the previous one. This implementation includes functions for encryption and decryption using the CBC mode.

## Features

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
