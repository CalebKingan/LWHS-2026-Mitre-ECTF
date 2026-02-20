# Lakota West High School 2026 ECTF Design

## Layout

- `firmware/` - Source code to build the firmware
    - `Makefile` - This makefile is invoked by the eCTF tools when creating an HSM.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `secrets_to_c_header.py` - Python file to convert from global secrets to firmware-parsable header file
    - `inc/` - Directory with C header files
    - `src/` - Directory with C source files
    - `wolfssl/` - Location to place the wolfssl library for the included Crypto Module
    - `firmware.ld` - Defines memory layout of built firmware
- `ectf26_design/` - Pip-installable module for generating secrets
    - `src/` - Secrets gen source code
        - `gen_secrets.py` - Generates shared secrets
    - `pyproject.toml` - File that tells pip how to install this module
- `Makefile` - Helper script to simplify repetitive build steps

## Installation

### Required Dependencies
`Docker` \
`UV` \
`Git Bash` 

### Creating a Deployment
`uv venv` \
`source .venv/Scripts/activate` \
`uv pip install -e ./ectf26_design` \
`uv run secrets ./global.secrets 1 2 3 0x1111` \
`docker build -t build-hsm ./firmware` 

### Building an HSM
`docker run --rm -v "$(pwd -W)\firmware:/hsm" -v "$(pwd -W)\global.secrets:/secrets/global.secrets:ro" -v "$(pwd -W)\build:/out" -e HSM_PIN=abc123 -e PERMISSIONS="1111=-W-" build-hsm` 

### Flashing an HSM
`uvx ectf hw COMX erase` \
`uvx ectf hw COMX flash .\build\hsm.bin -n hsm` \
`uvx ectf hw COMX start` 
