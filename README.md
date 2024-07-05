# Eyal the Singer

This is a password-cracking tool built for paralellization across CPU, GPU and possibly multiple devices connected on a network.

The tool is based on brute-force and does not use any sort of _weakness_ in the underlying mechanisms.

## Features

-   Cipher support
    -   [x] SHA256
    -   [ ] WPA2
-   Parallelization support
    -   [x] CPU parallelization
    -   [ ] CUDA
    -   [ ] Multiple devices

## Development Setup

-   Install [rye](https://rye.astral.sh/).
-   Run `rye sync` and use the virtual environment created in `.venv` (i.e. `source .venv/bin/activate` or `.venv\Scripts\activate`).
-   Compile the CPU crackers by running `clang -O3 crackers/*.c -o sing` (or `gcc -O3 crackers/*.c -o sing`).

Eyal the Singer was built as part of the Workshop in Implementation of Cryptographic Attacks at Tel Aviv University, hosted by Dr. Eyal Ronen.
