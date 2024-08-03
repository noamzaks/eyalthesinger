# Eyal the Singer

This is a password-cracking tool built for paralellization across CPU, GPU and possibly multiple devices connected on a network.

The tool is based on brute-force and does not use any sort of _weakness_ in the underlying mechanisms.

⚠️ This is created for educational purposes only. The code is provided without any guarantees and the person running the code bears all responsibility.

## Features

-   Cipher support
    -   [x] SHA256
    -   [x] SHA1
    -   [ ] WPA2
-   Parallelization support
    -   [x] CPU parallelization
    -   [ ] CUDA
    -   [ ] Multiple devices

## Development Setup

-   Install [rye](https://rye.astral.sh/).
-   Run `rye sync` and use the virtual environment created in `.venv` (i.e. `source .venv/bin/activate` or `.venv\Scripts\activate`).
-   Compile the CPU crackers by running `clang -O3 crackers/*.c -o sing` (or `gcc -O3 crackers/*.c -o sing`).

TODO: current build command is `gcc -O3 crackers/*.c -I/opt/homebrew/Cellar/openssl@3/3.3.1/include -L/opt/homebrew/Cellar/openssl@3/3.3.1/lib -lssl -lcrypto -o sing` at least on an ARM Mac.

Eyal the Singer was built as part of the Workshop in Implementation of Cryptographic Attacks at Tel Aviv University, hosted by Dr. Eyal Ronen.
