# Eyal the Singer

This is a password-cracking tool built for paralellization across CPU, GPU and possibly multiple devices connected on a network.

The tool is based on brute-force and does not use any sort of _weakness_ in the underlying mechanisms.

## Features

-   Cipher support
    -   [ ] SHA256
    -   [ ] WPA2
-   Parallelization support
    -   [ ] CPU parallelization
    -   [ ] CUDA
    -   [ ] Multiple devices

## Development Setup

-   Install [rye](https://rye.astral.sh/).
-   Run `rye sync` and use the virtual environment created in `.venv` (i.e. `source .venv/bin/activate` or `.venv\Scripts\activate`).

Eyal the Singer was built as part of the Workshop in Implementation of Cryptographic Attacks at Tel Aviv University, hosted by Dr. Eyal Ronen.
