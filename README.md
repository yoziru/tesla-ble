# TeslaBLE - A C++ library for communicating with Tesla vehicles over BLE
This library is designed to communicate with Tesla vehicles locally via the BLE API. It follows the same principles as the official Tesla [vehicle-command](https://github.com/teslamotors/vehicle-command) library (Golang), and is intended for use in embedded systems.

It exists to:
1. Provide a local and offline alternative to the official Tesla API.
2. Avoid the rate limits of the official Tesla API.

The main purpose of this library is to locally manage charging of the vehicle to enable use cases such as charging during off-peak hours, or to manage charging based on solar production. It is not intended to replace the official Tesla API for all use cases.

## Usage
This project is intended to be used as a library in your own project. It is not a standalone application. 

[yoziru/esphome-tesla-ble](https://github.com/yoziru/esphome-tesla-ble) is an ESPHome project that uses this library to control your Tesla vehicle charging.

Several examples are included for your convenience.
```sh
cd examples/simple/ 
cmake .
make
```


### Dependencies
- [nanopb](https://github.com/nanopb/nanopb)
- [mbedtls 3.x](https://github.com/Mbed-TLS/mbedtls)
  - NOTE: ESP-IDF <=4.4 includes [mbedtls 2.x](https://github.com/espressif/mbedtls/wiki#mbed-tls-support-in-esp-idf), and is not compatible with this library. You will need to use at least ESP-IDF 5.0.

## Features
- [x] Implements Tesla's BLE [protocol](https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md)
- [x] AES-GCM key generation
- [x] [Metadata serialization](https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md#metadata-serialization)
- [x] Supports `UniversalMessage.RoutableMessage` encoding and decoding
  - [x] Supports Vehicle Security (VSSEC) payload
  - [x] Supports Infotainment payload

# Credits
This fork builds on the original version by [pmdroid](https://github.com/pmdroid/tesla-ble/tree/main).

# IMPORTANT
Please take note that this library does not have official backing from Tesla, and its operational capabilities may be discontinued without prior notice. It's essential to recognize that this library retains private keys and other sensitive data on your device without encryption. I would like to stress that I assume no liability for any possible (although highly unlikely) harm that may befall your vehicle.
