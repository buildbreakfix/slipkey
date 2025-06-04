# Slipkey Python SDK

A Python implementation of the Slipkey protocol, providing tools for client-side slip generation and server-side slip validation. Slipkey is a lightweight proof-of-work mechanism designed for rate limiting and spam prevention.

This SDK allows developers to integrate Slipkey into their Python applications easily.

## Installation

To install the Slipkey Python SDK, you can use pip:

```bash
pip install slipkey-sdk-py
# Note: This package name is hypothetical. If publishing, choose an appropriate name on PyPI.
# For local development, you can install directly from the source:
# pip install .
# (Assuming a setup.py or pyproject.toml is present in the sdk-py directory)
```

## Features

*   **Slipkey Client**: Generate slips (proof-of-work) based on server-provided challenges.
*   **Slipkey Server**: Validate slips submitted by clients and manage client credits/state.
*   **Cryptographic Algorithms**: Supports both EdDSA (Ed25519) and RSA for signing and verification.
*   **Key Utilities**: Helper functions for generating, serializing, and deriving secret and public keys.
*   **Flexible Configuration**: Easily configure algorithm choices and key management.

## Quick Start / Usage

Below are some examples of how to use the Slipkey Python SDK.

### Key Generation

The SDK provides utilities to generate cryptographic keys.

```python
from slipkey_sdk.slipkey import (
    generate_secret_key,
    serialize_secret_key,
    generate_public_key
)

# For EdDSA (default)
eddsa_private_key_obj = generate_secret_key(algorithm='EdDSA')
# serialized_eddsa_private_key is a hex string
serialized_eddsa_private_key = serialize_secret_key(eddsa_private_key_obj, algorithm='EdDSA')
# serialized_eddsa_public_key is a hex string
serialized_eddsa_public_key_hex = generate_public_key(eddsa_private_key_obj, algorithm='EdDSA')

print(f"EdDSA Private Key (Hex): {serialized_eddsa_private_key}")
print(f"EdDSA Public Key (Hex): {serialized_eddsa_public_key_hex}")


# For RSA
rsa_private_key_obj = generate_secret_key(algorithm='RSA')
# serialized_rsa_private_key is PEM bytes
serialized_rsa_private_key_pem = serialize_secret_key(rsa_private_key_obj, algorithm='RSA')
# serialized_rsa_public_key is PEM bytes
serialized_rsa_public_key_pem = generate_public_key(rsa_private_key_obj, algorithm='RSA')

print(f"RSA Private Key (PEM):\n{serialized_rsa_private_key_pem.decode()}")
print(f"RSA Public Key (PEM):\n{serialized_rsa_public_key_pem.decode()}")
```

### Client Example

```python
import time
import datetime
from slipkey_sdk.slipkey import SlipkeyClient, generate_secret_key

# Initialize client (e.g., with EdDSA)
# You can generate a key or load an existing one (hex string for EdDSA private key)
client_sk_hex = "your_hex_encoded_eddsa_private_key" # Replace or generate
# client = SlipkeyClient(secret_key_input=client_sk_hex, algorithm='EdDSA')
# Or generate a new one if no key is provided
client = SlipkeyClient(secret_key_input=None, algorithm='EdDSA')
print(f"Client Public Key (EdDSA Hex): {client.public_key_serial}")

# Parameters typically provided by the server or application
start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) # Current time as a starting point
block_interval = 60  # Expected time to find a slip (seconds)
max_interval = 120   # Max time allowed for this slip generation window
progress_interval = 100 # How often (in ms) generate_slip should check for time limits / yield if non-blocking
target_score = 2.5     # Target score for the slip's hash

print(f"Attempting to generate a slip with target score: {target_score}")

# Generate a slip
# In a real application, this might be called in a loop or a separate thread/task
# until progress is 1.0 or target_score is met.
best_slip_found = {'score': 0}
current_progress_info = {'progress': 0}

# Loop for a short duration for example purposes
loop_start = time.time()
while time.time() - loop_start < 10 and current_progress_info['progress'] < 1.0 and best_slip_found['score'] < target_score:
    best_slip_found, current_progress_info = client.generate_slip(
        start_time=start_time,
        block_interval=block_interval,
        max_interval=max_interval,
        progress_interval=progress_interval, # In ms for the hashing loop within generate_slip
        target_score=target_score,
        best_slip=best_slip_found
    )
    print(f"Progress: {current_progress_info['progress']:.2f}, Current Best Score: {best_slip_found.get('score', 0):.2f}")
    if current_progress_info['progress'] >= 1.0:
        print("Max interval reached or target score met if progress is 1.")
        break
    time.sleep(0.1) # Simulate work or allow other tasks

if best_slip_found['score'] > 0:
    print(f"Successfully generated a slip with score: {best_slip_found['score']}")

    # Create a token (JWT) for the slip
    # 'create=True' for the first slip (genesis)
    # 'create=False' if including a 'state' JWT from a previous server response in the slip
    token = client.create_token(best_slip_found, create=True)
    print(f"Client Token: {token[:60]}...") # Print first 60 chars

    # Simulate processing a server response
    # Server response would typically come after sending the token
    mock_server_response = {
        'credit': 5,
        'creditEarned': 5,
        'state': 'server_signed_jwt_state_for_next_round',
        # ... other fields
    }
    current_credit, error = client.process_response(mock_server_response)
    if error:
        print(f"Error processing server response: {error}")
    else:
        print(f"Client credit after response: {current_credit}")
else:
    print("Failed to generate a slip with score > 0 in the example timeframe.")

```

### Server Example

```python
from slipkey_sdk.slipkey import SlipkeyServer, generate_secret_key

# Initialize server (e.g., with EdDSA)
# You can generate a key or load an existing one (hex string for EdDSA private key)
server_sk_hex = "your_server_hex_encoded_eddsa_private_key" # Replace or generate
# server = SlipkeyServer(secret_key_input=server_sk_hex, algorithm='EdDSA')
# Or generate a new one
server = SlipkeyServer(secret_key_input=None, algorithm='EdDSA')
print(f"Server Public Key (EdDSA Hex): {server.public_key_serial}")

# Example client token (replace with actual token from client)
# client_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmNkZWYoLi4uIn0.SIGNATURE"
# For this example, we'll skip actually providing a token as it needs a live client.

# Assume client_token is received from a client
# validation_result, error = server.validate_slip(client_token)
# if error:
#     print(f"Slip validation error: {error}")
# else:
#     print(f"Slip validated successfully! Response to send to client:")
#     print(validation_result)
#     # validation_result contains:
#     # {
#     # 'block': ..., 'len': ..., 'state': (new_state_jwt),
#     # 'score': ..., 'hash': ..., 'expires': ...,
#     # 'credit': ..., 'creditEarned': ...
#     # }
```
(To run the server example fully, you'd need a token generated by a client instance from the client example.)

## Running Tests

The SDK includes a suite of unit tests. To run them:

1.  Ensure you have the necessary dependencies installed (e.g., `cryptography`, `pyjwt`).
2.  Navigate to the root directory of the `sdk-py` package.
3.  Run the tests using Python's `unittest` module:

```bash
python -m unittest discover tests
```
Or, if your tests directory is at the same level as `slipkey_sdk`:
```bash
python -m unittest tests.test_slipkey
```

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you'd like to contribute code:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Write tests for your changes.
4.  Make your changes.
5.  Ensure all tests pass.
6.  Submit a pull request.

## License

This Slipkey Python SDK is released under the [MIT License](LICENSE.txt) (assuming, please verify and create a LICENSE.txt if it doesn't exist or refer to the parent project's license).
```
