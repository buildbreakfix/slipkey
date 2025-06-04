import jwt
import hashlib
import datetime
import random
import string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


# --- Utility Functions ---

def generate_secret_key(algorithm: str = 'EdDSA'):
    """
    Generates a private key for the specified algorithm.

    Args:
        algorithm: The algorithm to use ('EdDSA' or 'RSA').

    Returns:
        A private key object.
    """
    if algorithm == 'EdDSA':
        return ed25519.Ed25519PrivateKey.generate()
    elif algorithm == 'RSA':
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def serialize_secret_key(private_key, algorithm: str = 'EdDSA', encoding: serialization.Encoding = serialization.Encoding.PEM, key_format: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()):
    """
    Serializes a private key. For EdDSA, returns hex of raw bytes as PEM is not standard for raw EdDSA private keys.
    For RSA, returns PEM.

    Args:
        private_key: The private key object.
        algorithm: The algorithm of the key ('EdDSA' or 'RSA').
        encoding: The encoding to use (e.g., PEM, RawHex for EdDSA).
        key_format: The private key format.
        encryption_algorithm: The encryption algorithm for the private key.

    Returns:
        Serialized private key (bytes for PEM, str for Hex).
    """
    if algorithm == 'EdDSA':
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            # Standard for Ed25519 private keys is often raw bytes, then hex encoded
            # as there isn't a universally adopted PEM format for Ed25519 *private* keys specifically via PKCS#8 that all libs love.
            # However, public keys are fine with SubjectPublicKeyInfo.
            # For consistency with current __init__ which expects hex, we'll return hex of raw bytes.
            return private_key.private_bytes(
                encoding=serialization.Encoding.Raw, # Not PEM for private part
                format=serialization.PrivateFormat.Raw, # Not PKCS8 for private part
                encryption_algorithm=serialization.NoEncryption()
            ).hex()
        else:
            raise ValueError("Invalid key type for EdDSA serialization.")

    elif algorithm == 'RSA':
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.private_bytes(
                encoding=encoding,
                format=key_format,
                encryption_algorithm=encryption_algorithm
            )
        else:
            raise ValueError("Invalid key type for RSA serialization.")
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def generate_public_key(private_key, algorithm: str = 'EdDSA'):
    """
    Derives the public key from the private key and serializes it.
    For EdDSA, returns hex of raw bytes. For RSA, returns PEM.


    Args:
        private_key: The private key object.
        algorithm: The algorithm of the key ('EdDSA' or 'RSA').

    Returns:
        Serialized public key (str for Hex EdDSA, bytes for PEM RSA).
    """
    public_key = private_key.public_key()
    if algorithm == 'EdDSA':
        if isinstance(public_key, ed25519.Ed25519PublicKey):
             return public_key.public_bytes(
                encoding=serialization.Encoding.Raw, # EdDSA public keys often represented as raw bytes
                format=serialization.PublicFormat.Raw
            ).hex()
        else:
            raise ValueError("Invalid public key type for EdDSA.")

    elif algorithm == 'RSA':
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError("Invalid public key type for RSA.")
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


class SlipkeyClient:
    def __init__(self, secret_key_input, algorithm: str = 'EdDSA'):
        """
        Initializes the SlipkeyClient.

        Args:
            secret_key_input: The secret key. Can be a key object, or a string (hex for EdDSA, PEM for RSA).
                              If None, a new key will be generated.
            algorithm: The algorithm to use ('EdDSA' or 'RSA').
        """
        self.algorithm = algorithm

        if secret_key_input is None:
            self.signing_key = generate_secret_key(algorithm)
        elif isinstance(secret_key_input, str):
            if self.algorithm == 'EdDSA':
                try:
                    private_key_bytes = bytes.fromhex(secret_key_input)
                    self.signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                except ValueError as e:
                    raise ValueError(f"Invalid hex secret key format for EdDSA: {e}")
            elif self.algorithm == 'RSA':
                try:
                    self.signing_key = serialization.load_pem_private_key(
                        secret_key_input.encode(), # PEM data needs to be bytes
                        password=None
                    )
                    if not isinstance(self.signing_key, rsa.RSAPrivateKey):
                         raise ValueError("PEM data did not yield an RSA private key.")
                except Exception as e:
                    raise ValueError(f"Invalid PEM secret key format for RSA: {e}")
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        else: # Assuming key object is passed
            if self.algorithm == 'EdDSA' and not isinstance(secret_key_input, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided key is not an Ed25519PrivateKey.")
            elif self.algorithm == 'RSA' and not isinstance(secret_key_input, rsa.RSAPrivateKey):
                raise ValueError("Provided key is not an RSAPrivateKey.")
            self.signing_key = secret_key_input

        # Derive and store public key (hex for EdDSA, PEM bytes for RSA)
        # For consistency in JWT 'sub' and slip 'public_key', we will use hex for EdDSA raw public key
        # and PEM for RSA public key. The server side will need to handle this.
        _public_key_obj = self.signing_key.public_key()
        if self.algorithm == 'EdDSA':
            self.public_key_serial = _public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ).hex()
        elif self.algorithm == 'RSA':
            self.public_key_serial = _public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode() # Store as string
        else:
            raise ValueError(f"Unsupported algorithm for public key serialization: {self.algorithm}")


        self.credit = 0

    def _calculate_score(self, data_to_hash: str) -> int:
        """Helper function to calculate score from hash."""
        hash_value = hashlib.sha256(data_to_hash.encode()).hexdigest()
        # Score is the number of leading zeros in the binary representation of the hash
        # This is a common PoW scoring mechanism.
        # For simplicity, we'll use a part of the hex hash and convert to int.
        # A more robust scoring would count leading zeros.
        score = 0
        for char in hash_value:
            if char == '0':
                score +=1
            else:
                break
        #Simulate a more granular score based on the first non-zero hex digit
        if len(hash_value) > score:
            first_non_zero_digit = hash_value[score]
            score += (15 - int(first_non_zero_digit, 16))/15.0

        return score, hash_value


    def generate_slip(self, start_time: int, block_interval: int, max_interval: int, progress_interval: int, target_score: int, best_slip: dict = None):
        """
        Generates a slip by performing hashing.

        Args:
            start_time: The start time of the slip generation.
            block_interval: The interval for hashing blocks.
            max_interval: The maximum interval for slip generation.
            progress_interval: The interval for reporting progress.
            target_score: The target score to achieve.
            best_slip: The current best slip found.

        Returns:
            A tuple containing the best slip found and progress information.
        """
        if best_slip is None:
            best_slip = {'score': 0}

        current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if current_time < start_time:
            # It's not time to start yet
            return best_slip, {'progress': 0, 'current_score': best_slip['score']}

        time_elapsed = current_time - start_time
        if time_elapsed > max_interval:
            # Max interval reached
            return best_slip, {'progress': 1, 'current_score': best_slip['score']}

        # More realistic hashing logic
        # We are looking for a hash with a certain number of leading zeros (or a high score)
        # This loop will run until time_elapsed > progress_interval or target_score is met
        # It should not block for the entire max_interval in one call.
        # The caller is expected to call this method multiple times.

        loop_start_time = datetime.datetime.now(datetime.timezone.utc).timestamp()

        while True:
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32)) # Increased nonce size
            data_to_hash = f"{self.public_key_serial}{start_time}{nonce}" # Hash public_key, start_time, and nonce

            score, hash_value = self._calculate_score(data_to_hash)

            if score > best_slip.get('score', 0): # Use .get for initial case
                best_slip = {
                    'score': score,
                    'nonce': nonce,
                    'hash': hash_value, # Store the actual hash
                    'start_time': start_time, # This is the 'block' in server terms
                    'public_key': self.public_key_serial, # Use serialized public key
                    'algorithm': self.algorithm
                }

            current_loop_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
            if current_loop_time - loop_start_time > progress_interval / 1000.0 : # progress_interval is in ms in example
                 # If we spent enough time in this call, return for progress update
                 break
            if best_slip.get('score',0) >= target_score:
                break


        # Calculate overall progress
        current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
        time_elapsed = current_time - start_time
        progress = min(time_elapsed / max_interval, 1.0)
        if best_slip.get('score',0) >= target_score :
            progress = 1.0

        return best_slip, {'progress': progress, 'current_score': best_slip.get('score',0)}

    def create_token(self, slip: dict, create: bool = False) -> str:
        """
        Creates a JWT token.

        Args:
            slip: The slip object.
            create: A flag indicating if this is a creation token (optional).

        Returns:
            A JWT string.
        """
        if not slip or 'score' not in slip:
            raise ValueError("Invalid slip object.")

        payload = {
            'iat': datetime.datetime.now(datetime.timezone.utc),
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60), # Token expires in 60 seconds
            'sub': self.public_key_serial, # The client's serialized public key
            'slip': slip # The actual slip object
        }
        if create:
            payload['create'] = True # Indicate this is for creating a new state

        # For EdDSA/RSA with PyJWT and cryptography, we pass the key object directly
        # PyJWT determines the correct JWT alg (e.g. "EdDSA", "RS256") from the key type/algorithm specified
        jwt_algorithm = self.algorithm
        if self.algorithm == 'RSA':
            jwt_algorithm = 'RS256' # Be explicit for RSA

        token = jwt.encode(payload, self.signing_key, algorithm=jwt_algorithm)
        return token

    def process_response(self, response: dict) -> tuple[int, str | None]:
        """
        Processes the server's response.

        Args:
            response: The server's response dictionary.

        Returns:
            A tuple containing the extracted credit and any potential error message.
        """
        if not response:
            return self.credit, "Empty response from server."

        if 'error' in response:
            return self.credit, response['error']

        if 'credit' in response:
            new_credit = response.get('credit', 0)
            if isinstance(new_credit, (int, float)):
                 self.credit = new_credit
            else:
                return self.credit, "Invalid credit format in response."

        # The server might also send back a new state token or other info,
        # but for this client, we're primarily interested in the credit.
        # We could also store/validate the 'state' if provided.
        if 'state' in response:
            # Potentially decode and store this state for future use,
            # though the current client logic doesn't use it directly after processing.
            pass

        return self.credit, None


class SlipkeyServer:
    def __init__(self, secret_key_input, algorithm: str = 'EdDSA'):
        """
        Initializes the SlipkeyServer.

        Args:
            secret_key_input: The server's secret key. Can be a key object or string (hex for EdDSA, PEM for RSA).
                              If None, a new key will be generated.
            algorithm: The algorithm to use for signing state tokens ('EdDSA' or 'RSA').
        """
        self.algorithm = algorithm

        if secret_key_input is None:
            self.signing_key = generate_secret_key(algorithm)
        elif isinstance(secret_key_input, str):
            if self.algorithm == 'EdDSA':
                try:
                    private_key_bytes = bytes.fromhex(secret_key_input)
                    self.signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                except ValueError as e:
                    raise ValueError(f"Invalid hex secret key format for EdDSA server key: {e}")
            elif self.algorithm == 'RSA':
                try:
                    self.signing_key = serialization.load_pem_private_key(
                        secret_key_input.encode(),
                        password=None
                    )
                    if not isinstance(self.signing_key, rsa.RSAPrivateKey):
                         raise ValueError("PEM data did not yield an RSA private key for server.")
                except Exception as e:
                    raise ValueError(f"Invalid PEM secret key format for RSA server key: {e}")
            else:
                raise ValueError(f"Unsupported server algorithm: {self.algorithm}")
        else: # Assuming key object
            if self.algorithm == 'EdDSA' and not isinstance(secret_key_input, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided server key is not an Ed25519PrivateKey.")
            elif self.algorithm == 'RSA' and not isinstance(secret_key_input, rsa.RSAPrivateKey):
                raise ValueError("Provided server key is not an RSAPrivateKey.")
            self.signing_key = secret_key_input

        # Server's public key (primarily for clients to verify server-signed states if needed, though not used in this example)
        _public_key_obj = self.signing_key.public_key()
        if self.algorithm == 'EdDSA':
            self.public_key_serial = _public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ).hex()
        elif self.algorithm == 'RSA':
             self.public_key_serial = _public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            raise ValueError(f"Unsupported algorithm for server public key: {self.algorithm}")

        # In-memory store for seen nonces to prevent replay attacks for a short window
        # This should be replaced with a more persistent cache (e.g., Redis) in production
        self.seen_nonces = {} # Store as {nonce: timestamp}
        self.nonce_expiry_seconds = 300 # Nonces expire after 5 minutes


    def _verify_and_decode_client_token(self, token: str, client_public_key_serial: str, client_algorithm: str) -> dict:
        """Verifies and decodes a token using the client's public key (serialized)."""
        try:
            verifying_key = None
            jwt_algo_to_check = client_algorithm
            if client_algorithm == 'EdDSA':
                public_key_bytes = bytes.fromhex(client_public_key_serial)
                verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                # PyJWT uses "EdDSA" for this
            elif client_algorithm == 'RSA':
                verifying_key = serialization.load_pem_public_key(client_public_key_serial.encode())
                if not isinstance(verifying_key, rsa.RSAPublicKey):
                    raise ValueError("Client public key is not a valid RSA PEM.")
                jwt_algo_to_check = 'RS256' # Common JWT alg for RSA
            else:
                raise ValueError(f"Unsupported client algorithm for token verification: {client_algorithm}")

            payload = jwt.decode(token, verifying_key, algorithms=[jwt_algo_to_check])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Client token has expired.")
        except jwt.InvalidSignatureError:
            raise ValueError("Client token signature is invalid.")
        except Exception as e:
            raise ValueError(f"Client token decoding/verification failed: {e}")

    def _calculate_score(self, data_to_hash: str) -> int:
        """Helper function to calculate score from hash. Mirrors client's _calculate_score."""
        hash_value = hashlib.sha256(data_to_hash.encode()).hexdigest()
        score = 0
        for char in hash_value:
            if char == '0':
                score +=1
            else:
                break
        if len(hash_value) > score:
            first_non_zero_digit = hash_value[score]
            score += (15 - int(first_non_zero_digit, 16))/15.0
        return score, hash_value

    def _cleanup_expired_nonces(self):
        """Removes expired nonces from the seen_nonces store."""
        current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
        expired_nonces = [
            nonce for nonce, timestamp in self.seen_nonces.items()
            if current_time - timestamp > self.nonce_expiry_seconds
        ]
        for nonce in expired_nonces:
            del self.seen_nonces[nonce]

    def validate_slip(self, token: str) -> tuple[dict | None, str | None]:
        """
        Validates a slip JWT (token).

        Args:
            token: The slip JWT from the client.

        Returns:
            A tuple containing block information and None for error,
            or None and an error message if validation fails.
        """
        self._cleanup_expired_nonces()
        try:
            # 1. Decode token without signature verification to get public key
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            client_public_key_serial = unverified_payload.get('sub') # This is the serialized public key
            slip_data = unverified_payload.get('slip')

            if not client_public_key_serial or not isinstance(client_public_key_serial, str):
                return None, "Missing or invalid 'sub' (client public key) in token."
            if not slip_data or not isinstance(slip_data, dict):
                return None, "Missing or invalid 'slip' data in token."

            client_algorithm = slip_data.get('algorithm') # Algorithm used by client for this slip
            if not client_algorithm:
                return None, "Missing 'algorithm' in slip data."


            # 2. Verify token signature using the extracted public key and its algorithm
            payload = self._verify_and_decode_client_token(token, client_public_key_serial, client_algorithm)
            # Re-fetch slip_data from verified payload for security
            slip_data = payload.get('slip')
            if slip_data.get('public_key') != client_public_key_serial: # Compare serialized forms
                 return None, "Token 'sub' does not match 'public_key' in slip data."


            # 3. Extract slip components
            nonce = slip_data.get('nonce')
            block_timestamp = slip_data.get('start_time') # This is the 'block' identifier
            client_hash = slip_data.get('hash')
            client_score = slip_data.get('score')
            is_create = payload.get('create', False)
            client_state_jwt = slip_data.get('state') # This is the JWT state from previous turn

            if not all([nonce, isinstance(block_timestamp, (int, float)), client_hash, isinstance(client_score, (int,float))]):
                return None, "Invalid or missing components in slip data (nonce, start_time, hash, score)."

            # Prevent replay attacks using nonce
            if nonce in self.seen_nonces:
                return None, "Replayed nonce. This slip has already been processed."


            # 4. Verify 'block' (start_time) is not in the future (allowing for small clock skew)
            current_server_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
            if block_timestamp > current_server_time + 60: # Allow 60s clock skew
                return None, f"Slip 'start_time' ({block_timestamp}) is too far in the future."

            # 5. Recalculate hash and verify score
            # The data hashed by the client was: f"{client_public_key_serial}{start_time}{nonce}"
            # This must use the same serialized form of the public key that the client used.

            data_to_hash = f"{client_public_key_serial}{block_timestamp}{nonce}"
            recalculated_score, recalculated_hash = self._calculate_score(data_to_hash)

            if recalculated_hash != client_hash:
                return None, f"Hash mismatch. Client: {client_hash}, Server: {recalculated_hash}."

            # Server recalculates score independently. Minor floating point differences might occur.
            # It's often better to trust the client's claimed score if the hash matches,
            # or re-evaluate based on the hash properties (e.g. leading zeros).
            # For now, let's ensure client's score isn't wildly different from recalculated.
            if abs(recalculated_score - client_score) > 0.00001 : # Tolerance for float comparison
                 # Potentially log this discrepancy. For now, we can use the client's claimed score
                 # if the hash is valid, or be strict and use server's. Let's use server's.
                 pass # We will use recalculated_score

            if not (recalculated_score > 0): # Score must be positive
                return None, "Invalid score (must be > 0)."


            # 6. Handle 'create' flag and 'state'
            previous_credit = 0
            if is_create:
                if client_state_jwt is not None:
                    return None, "State must be absent when 'create' flag is True."
            else: # Not a create request, so state must be present
                if client_state_jwt is None:
                    return None, "State must be present when 'create' flag is False."
                try:
                    # Validate the incoming state JWT (signed by this server)
                    # The 'key' for decoding server's own state token is its own public key.
                    # The algorithm for the state token is self.algorithm (server's algorithm).
                    server_verifying_key_for_state = self.signing_key.public_key()

                    jwt_state_algo_to_check = self.algorithm
                    if self.algorithm == 'RSA':
                        jwt_state_algo_to_check = 'RS256'


                    state_payload = jwt.decode(
                        client_state_jwt,
                        server_verifying_key_for_state,
                        algorithms=[jwt_state_algo_to_check]
                    )

                    # Check if the public key in the state matches the slip's public key (client's PK)
                    if state_payload.get('sub') != client_public_key_serial:
                        return None, "Public key in state does not match current client's public key."

                    # Check if the state is expired (e.g. based on 'iat' and a TTL)
                    # For simplicity, we assume state doesn't expire here beyond token expiry.
                    # A 'block' or 'len' check could also be done to ensure sequence.
                    # For example, if block_timestamp <= state_payload.get('block'): return None, "Stale state"

                    previous_credit = state_payload.get('credit', 0)

                except jwt.ExpiredSignatureError:
                    return None, "Provided state token has expired."
                except jwt.InvalidTokenError as e:
                    return None, f"Invalid state token: {e}"


            # 7. If all checks pass, calculate credit earned
            # Credit can be based on score, or other metrics. Example: 2 * score
            # Ensure score is treated as a float if it can be.
            credit_earned = 2 * float(recalculated_score)
            current_total_credit = previous_credit + credit_earned

            # 8. Generate new state object
            # The 'block' for the new state should be the current slip's block_timestamp
            # 'len' could be the duration this slip is valid for or some other metric
            # For now, let's make 'len' the block_interval the client should aim for next.
            # A server would typically define this.
            new_block_identifier = block_timestamp # The block just validated
            next_len_suggestion = 60 # Suggest next slip to be valid for 60s of work.

            new_state_payload = {
                'iat': datetime.datetime.now(datetime.timezone.utc).timestamp(),
                'exp': datetime.datetime.now(datetime.timezone.utc).timestamp() + datetime.timedelta(days=1), # State valid for 1 day
                'sub': client_public_key_serial, # Subject is the client's public key (serialized)
                'credit': current_total_credit,
                'block': new_block_identifier, # Last validated block
                'len': next_len_suggestion, # Suggestion for next interval length
                'server_algorithm': self.algorithm # Store server's algo for clarity if needed
            }

            # 9. Encode new state into a JWT using the server's private key and its algorithm
            jwt_server_state_algorithm = self.algorithm
            if self.algorithm == 'RSA':
                jwt_server_state_algorithm = 'RS256'

            new_state_jwt = jwt.encode(new_state_payload, self.signing_key, algorithm=jwt_server_state_algorithm)

            # Add nonce to seen list after successful processing
            self.seen_nonces[nonce] = current_server_time


            # 10. Return block information
            response_data = {
                'block': new_block_identifier,
                'len': next_len_suggestion,
                'state': new_state_jwt,
                'score': recalculated_score,
                'hash': client_hash, # Echo back the client's hash
                'expires': block_timestamp + next_len_suggestion, # When this new state effectively expires for submission
                'credit': current_total_credit,
                'creditEarned': credit_earned
            }
            return response_data, None

        except ValueError as e:
            return None, str(e)
        except jwt.DecodeError as e: # Catch errors from the initial unverified decode
            return None, f"Invalid token format: {e}"
        except Exception as e:
            # Log the exception e for server-side debugging
            print(f"Unexpected server error: {e}") # TODO: Replace with actual logging
            return None, "An unexpected error occurred on the server."
