# slipkey example (python)

This is a Python implementation of the `slipkey` protocol, including a `Client` and `Server` class. The implementation demonstrates how to generate and validate proof-of-work solutions using JWTs and SHA-256 hashing.

## Installation

To install the required dependencies, run:

```bash
pip install pyjwt click
```

## Usage

Running the Example

The `example.py` file contains an example implementation of Client and Server classes implementing the `slipkey` protocol. You can use it to simulate the interaction between a client and a server.

1. **Start the Server**: The server is initialized with a secret key and waits for client submissions.
2. **Run the Client**: The client generates a proof-of-work solution and submits it to the server.

```bash
% python example.py
[Client] Client secret key generated
[Server] Server secret key generated
[Client] Generating slip...
[1] 00000005 hashes, Score=1, 0.99992 remaining
[Client] Slip (U5QYrR0ASTtFo0pa) generated with score=1 in 0.00 seconds
[Server] Slip accepted
[Server] Credit=2, Block=2025-04-27T00:09:37.879045, Len=1
[Client] Credit=2
[Client] Generating slip...
[1] 00000016 hashes, Score=1, 0.999785 remaining
[Client] Slip (6mSZf5HdL2Ityco2) generated with score=1 in 0.00 seconds
[Server] Slip accepted
[Server] Credit=4, Block=2025-04-27T00:09:38.885002, Len=2
[Client] Credit=4
[Client] Generating slip...
[1] 00000011 hashes, Score=1, 0.999161 remaining
[Client] Slip (LiW5GEQkSYj6X01T) generated with score=1 in 0.00 seconds
[Server] Slip accepted
[Server] Credit=6, Block=2025-04-27T00:09:39.893450, Len=3
[Client] Credit=6
[Client] Generating slip...
[1] 00000018 hashes, Score=1, 0.999501 remaining
[Client] Slip (nyL40R2ue5BoBCOM) generated with score=1 in 0.00 seconds
[Server] Slip accepted
[Server] Credit=8, Block=2025-04-27T00:09:40.909327, Len=4
[Client] Credit=8
[Client] Generating slip...
[1] 00000002 hashes, Score=1, 0.999755 remaining
[Client] Slip (rdghnJ9AvawxGO3E) generated with score=1 in 0.00 seconds
[Server] Slip accepted
[Server] Credit=10, Block=2025-04-27T00:09:41.922530, Len=5
[Client] Credit=10
```

## Requirements

Python 3.7+
pyjwt for JWT encoding/decoding
click for optional CLI functionality

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request.

## References
For more details on the slipkey protocol, see the main README.md in the parent directory.