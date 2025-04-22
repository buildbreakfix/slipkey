# slipkey

![Slipkey Logo](assets/logo.png)

## Overview
The slipkey standard enables an unlimited number of anonymous clients to interact with a stateless server. It is built on three foundational concepts:

1. **Hash Functions**: Used to solve computational problems that validate client actions.
2. **Proof of Work**: Ensures that clients expend computational effort to earn credit, discouraging abuse.
3. **JSON Web Tokens (JWTs)**: Used to securely store and transmit server state.

With slipkey, an anonymous client generates an account by creating a key pair (similar to a cryptocurrency wallet). The client then solves a hashing problem involving its public key, the current time, and the last problem solved. This process verifies and credits the account.

The server validates the solution to the hashing problem and issues a new JWT containing the last solved hash and the credits earned. The client continues this process, submitting solutions and server-signed state (referred to as "slips") to earn additional credit. Since the proof-of-work solution depends on the server's current state, the server can verify both the solution and the state, advancing the protocol.

Effectively, the client and server cooperatively build a blockchain, where the most recent JWT from the server acts as the "block." The client performs all computational work and stores the blocks, which disincentivizes server abuse by requiring proof of work for all credits earned.

### Use Cases

Slipkey can be applied to various scenarios, including:

- **Anonymized Voting**: Ensures secure and anonymous participation in voting systems.
- **Rate Limiting** of anonymized users
- **Distributed, Anonymous Authentication** at the CDN level
- **Stateless Authentication** (no storage or retrieval cost)

## How it works?

### Step 1: Client solution
First, the client generates a public and private key pair. The private key is stored securely.

Next, the client selects a "block" to solve. Blocks are time windows (between the current time and some time in the future) of variable size, which must be greater than the last solved block. The block size is selectable by the client, who makes the following tradeoff:

- A block too far in the future, solved too quickly, leaves some time wasted.
- A block close to the current time might not be solvable before that time arrives.

The initial ("genesis") block must contain the "create" flag. The initial block does not contain any server state.

An example initial request from the client can be seen below:

```json
// POST /.slipkey/auth
{
    "block": "2025-04-13 00:00",
    "publicKey": "abcdef0123456789",
    "nonce": "XXXXXXXXXXXXXXX",
    "state": null,
    "create": true // First submission only (account creation)
}
```

The client combines the `publicKey`, the `block`, and the `state` signature with a `nonce` and hashes the result. The `nonce` is randomly selected to maximize the value of the solution. The value of the solution is determined by the number of leading zeros in the result. For example:

```
Score:
0 - XXXXXXXXXXXXXXXX
1 - 0XXXXXXXXXXXXXXX
2 - 00XXXXXXXXXXXXXX
...
```

### Step 2: Server verification

First, if any `state` is provided, the state is extracted as a JWT and verified. If the verification fails, either by signature or expiration, the API returns an error (e.g. `HTTP 401`).

Next, the server verifies the proposed `block` is in the future, if not, the API returns an error (e.g. `HTTP 401`).

The server then combines the `publicKey`, `block`, `state` signature, and `nonce` and hashes the result. Submissions with a score of 0 are ignored and the API returns an error (e.g. `HTTP 401`).

Any solution with a non-zero score counts as valid solution.

Once the server has verified the block timing and solution, a new JWT is issued as follows:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
.
{
  "iat": 1516239022, // The timestamp when the key was issued
  "publicKey": "abcdef0123456789", // The publicKey of the client
  "block": "2025-04-13 10:00:00", // The (latest) block that was solved
  "len": 1, // The number of blocks (length of chain) solved using this key
}
```

The server then returns this JWT back to the client

```json
// 200 HTTP Response
{
    "block": "2025-04-13 10:00:00",
    "len": 1,
    "state": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
    // Optional
    "expires":  1517239022 // Timestamp when the token expires. Server selectable.
}
```

### (OPTIONAL) Step 3: Crediting

While the aforementioned proof-of-work approach is sufficient for some use cases, it is often desirable to "credit" an account based on the work it has done. This "credit" takes into account the score of the hashing problem solved.

Keeping track of credit earned is straightforward - if enabled, the server `state` tracks credit and returns the current value.

```json
{
    "block": "2025-04-13 10:00:00",
    "len": 1,
    ...
    "credit": 1234567
}
```

Based on use case, the server determines how to increment credit based on any combination of the following:

- How long it has been since the last block was solved (incentivizing time worked)
- The score of the current, solved, blocked (incentivizing solutions produced)
- The length of the chain (incentivizing long-time users)
- The "publicKey" (incentivizing certain accounts)


**The "Double Spend" Problem**

Unfortunately, tracking credit consumption is not straightforward due to the well-known "Double Spend" problem. Consider server state `A` and state `B` where `A` -> `B` (`A` links to `B`) and `B` is the latest block.

If in `B` the credit was deremented, there is nothing preventing block `A` from being re-submitted with a new solution (e.g. changing the `block` to another time slightly in the future). This process could be repeated indefinitely and the server would have no way to know.

Therefore in this method, it is recommended that servers retain a table of "debits" for each private key.

|       Public Key      |       Debits         |
| --------------------- | -------------------- |
| abcdef0123456789      |          24          |
| 1234567890abcdef      |         365          |
| 2345678901abcdef      |         235          |

While this design may not seem obvious at first glance, it solves an important problem compared to storing the "balance" of each account. Using this method, both `credit` and `debit` are monotonically increasing numbers. This means that `credit` can be earned (via the "slip" method above) without any state retrieval from the server.

A write to the `debit` state in the server is only necessary when the user performs some action in the system. Typically that action will also require a write to the database, which will not incur any additional work on the server or its database. Furthermore, the monotonicity of the debits allows existing features like atomic and constraints to be used for implementation.

With `credits` and `debits` in mind, to determine if an action can be performed, the server simply compares the cost of the action, `credits` and `debits`:

> `credits` > `debits` + (cost of action)

If the above statement is `false`, the account does not have enough credits to perform the action.
If the above statement is `true`, the `debit` row is increemented by the cost of the action and the action is performed. 


## Error Handling

**How should the client react to a 401?**

If the server responds with a `401` error, the client should take the following steps:

1. **Re-submit the last solved problem**: The client should first attempt to re-submit the most recent solution to the server. This ensures that any transient issues, such as network errors or temporary server unavailability, are addressed.

2. **Revert and re-submit previous blocks**: If the server continues to reject the solution with a `401` error, the client should revert to the previous block and re-submit it. This process should be repeated iteratively, working backward through the chain of blocks, until all blocks are successfully submitted or the issue is resolved.

By following this approach, the client ensures that no valid solutions are lost and that the server state is synchronized correctly.

## Implementation

**Python**
[TODO write this]

**Javascript (Browser)**
- use WebAssembly / WebGPU for hashing?
[TODO write and finish this by considering the bullets above]

## FAQ

**What happens if the client does not provide a solution before time runs out?**
If the client does not provide a solution before the time runs out, the client must select a new block and begin searching for a solution again. The new block must be in the future and greater than the last solved block. The client should ensure that the new block is chosen with enough buffer to account for the time required to solve the problem and any potential network latency when submitting the solution to the server. This process ensures that the protocol remains synchronized and the client can continue earning credit without disruption.

**What happens if the server errors while processing the result?**
If the server errors while processing the result, the client can re-submit the same solution as long as the block's time window remains valid. The server will overwrite any state it may have stored with the newly submitted solution. This ensures that transient errors or issues on the server side do not result in a loss of valid solutions or disrupt the protocol's flow. The client should monitor the server's response and handle retries gracefully to maintain synchronization with the server state.

**What happens if a "solution" is submitted twice?**
The server state can only be advanced once using the previous block. As a result, the client is able to generate as many "next blocks" as they would like. However, the length of the block and any associated credit will not advance.

**What happens if there is clock drift between the client and the server?**
The protocol is designed for the server to be authoritative when it comes to time. This means that the server will reject any blocks with timestamps that are in the past relative to its own clock. To account for potential clock drift, the client must ensure that it selects blocks with enough buffer to accommodate the time required to solve the problem and any network latency when submitting the solution. By doing so, the client minimizes the risk of its solutions being rejected due to clock discrepancies.

**What happens if the client gets extremely lucky and achieves a very high score in a short period of time?**
While improbable, it is possible for clients to arrive at a high scoring solution in a very short period of time. The server can control for these "lucky" outcomes by enforcing a maximum score for each submission or assigning credits dynamically based on chain length, or time since last solve, in addition to the score.