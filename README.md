<h1 align="center">
  Eyal The Singer
  <br />
  <img alt="build status" src="https://img.shields.io/github/actions/workflow/status/noamzaks/eyalthesinger/build.yml">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg">
</h1>

This is a password-cracking tool built for paralellization across CPU, GPU and possibly multiple devices connected on a network.

The tool is based on brute-force and does not use any sort of _weakness_ in the underlying mechanisms.

⚠️ This is created for educational purposes only. The code is provided without any guarantees and the person running the code bears all responsibility.

## Features

-   Cipher support
    -   [x] SHA256
    -   [x] SHA1
    -   [x] WPA2
-   Parallelization support
    -   [x] CPU parallelization
    -   [ ] CUDA
    -   [x] Multiple devices

## Demo

### Cracking Basic Ciphers

-   Run `eyalthesinger download rockyou`.
-   Run `eyalthesinger crack sha256 rockyou.txt 3de3311f7965ecad3ff387be58e223acdfbaaef359a4bc1209284593dd76c15b`.

### Cracking WPA2

-   Get a `pcap` containing a 4-way handshake.
-   Run `eyalthesinger format wpa example.pcap`.
-   Run `eyalthesinger download rockyou`.
-   For example, run `eyalthesinger crack wpa rockyou.txt 4275696c64696e675f473200:20c19b58d6a3:28b37120f22c:3f045e6b81f56f7cebbbdbb9dbfb62b3db8a392c339962b1b5a3addfc2e397b0:5835a601df741dcf5f50495ba70dd8745a739e6770e0daf8ccda88010009c271:0103007502010a000000000000000000013f045e6b81f56f7cebbbdbb9dbfb62b3db8a392c339962b1b5a3addfc2e397b0000000000000000000000000000000000000000000000000000000000000000071b1942d7ad8f86e6c288ae3f61c2ec7001630140100000fac040100000fac040100000fac028000:71b1942d7ad8f86e6c288ae3f61c2ec7`.

### Networking

-   Run `eyalthesinger server`.
-   Run `eyalthesinger connect` (if you have multiple devices on the network, connect the others as well).
-   In the server, run `download rockyou`.
-   In the server, run `crack sha256 rockyou.txt 3de3311f7965ecad3ff387be58e223acdfbaaef359a4bc1209284593dd76c15b`.

## Development Setup

-   Install [rye](https://rye.astral.sh/).
-   Run `rye sync` and use the virtual environment created in `.venv` (i.e. `source .venv/bin/activate` or `.venv\Scripts\activate`).
-   Compile the CPU crackers by running `clang -O3 crackers/*.c -I. -o sing` (or `gcc -O3 crackers/*.c -I. -o sing`).

Eyal the Singer was built as part of the Workshop in Implementation of Cryptographic Attacks at Tel Aviv University, hosted by Dr. Eyal Ronen.
