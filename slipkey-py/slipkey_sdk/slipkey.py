import jwt
import hashlib
import datetime
import random
import string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.backends import default_backend
import base64
import json
from dataclasses import dataclass
from typing import Callable


# --- Configuration Dataclasses ---

@dataclass
class ServerCreditMetadata:
    block_timestamp: str # ISO format string of the block solved
    time_solved: datetime.datetime # UTC datetime object when the server validated the slip
    pow_score: int
    chain_length: int # The 'len' of the new state being issued
    client_public_key_claim_value: dict | str # JWK dict for RSA, hex str for EdDSA
    previous_credit: float | int
    previous_chain_length: int
    is_below_target_score: bool
    # Consider adding nonce: str if useful for credit calculation, though typically not.

@dataclass
class SlipkeyClientConfig:
    secret_key_input: str | object | None = None
    algorithm: str = 'RSA' # Default to RSA as it's primary for JWK alignment
    default_target_score: int = 1
    default_max_pow_iterations: int = 1000000

@dataclass
class SlipkeyServerConfig:
    secret_key_input: str | object | None = None
    algorithm: str = 'RSA' # Default to RSA
    default_state_token_expiration_seconds: int = 24 * 60 * 60 * 7 # 7 days
    custom_credit_calculator: Callable[[ServerCreditMetadata], float | int] | None = None
    default_expected_target_score: int = 1


# --- PEM-JWK Conversion Utilities ---

def pem_to_jwk(pem_public_key_str: str) -> dict:
    """
    Converts an RSA public key from PEM format to JWK format.
    """
    public_key = serialization.load_pem_public_key(
        pem_public_key_str.encode('utf-8'),
        backend=default_backend()
    )

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("PEM key is not an RSA public key.")

    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e

    # Ensure n and e are positive for proper byte conversion
    if n <= 0 or e <= 0:
        raise ValueError("RSA public key components (n, e) must be positive.")

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')

    n_b64url = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')
    e_b64url = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode('utf-8')

    jwk = {
        "kty": "RSA",
        "n": n_b64url,
        "e": e_b64url,
        "alg": "RS256",
    }
    return jwk

def jwk_to_pem(jwk_dict: dict) -> str:
    """
    Converts an RSA public key from JWK format to PEM format.
    """
    if not isinstance(jwk_dict, dict):
        raise ValueError("JWK must be a dictionary.")
    if jwk_dict.get("kty") != "RSA":
        raise ValueError("JWK 'kty' must be 'RSA'.")
    if 'n' not in jwk_dict or 'e' not in jwk_dict:
        raise ValueError("JWK must contain 'n' and 'e' fields.")

    n_b64url = jwk_dict['n']
    e_b64url = jwk_dict['e']

    # Add padding if necessary for base64.urlsafe_b64decode
    n_bytes = base64.urlsafe_b64decode(n_b64url + '=' * (-len(n_b64url) % 4))
    e_bytes = base64.urlsafe_b64decode(e_b64url + '=' * (-len(e_b64url) % 4))

    n_int = int.from_bytes(n_bytes, byteorder='big')
    e_int = int.from_bytes(e_bytes, byteorder='big')

    public_numbers = rsa.RSAPublicNumbers(e=e_int, n=n_int)
    public_key = public_numbers.public_key(backend=default_backend())

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

# --- End PEM-JWK Conversion Utilities ---


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
    def __init__(self, config: SlipkeyClientConfig):
        """
        Initializes the SlipkeyClient.

        Args:
            config: Configuration object for the client.
        """
        self.config = config
        self.algorithm = config.algorithm
        self.default_target_score = config.default_target_score
        self.default_max_pow_iterations = config.default_max_pow_iterations

        if config.secret_key_input is None:
            self.signing_key = generate_secret_key(self.algorithm)
        elif isinstance(config.secret_key_input, str):
            if self.algorithm == 'EdDSA':
                try:
                    private_key_bytes = bytes.fromhex(config.secret_key_input)
                    self.signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                except ValueError as e:
                    raise ValueError(f"Invalid hex secret key format for EdDSA: {e}")
            elif self.algorithm == 'RSA':
                try:
                    self.signing_key = serialization.load_pem_private_key(
                        config.secret_key_input.encode(), # PEM data needs to be bytes
                        password=None
                    )
                    if not isinstance(self.signing_key, rsa.RSAPrivateKey):
                         raise ValueError("PEM data did not yield an RSA private key.")
                except Exception as e:
                    raise ValueError(f"Invalid PEM secret key format for RSA: {e}")
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        else: # Assuming key object is passed
            if self.algorithm == 'EdDSA' and not isinstance(config.secret_key_input, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided key is not an Ed25519PrivateKey.")
            elif self.algorithm == 'RSA' and not isinstance(config.secret_key_input, rsa.RSAPrivateKey):
                raise ValueError("Provided key is not an RSAPrivateKey.")
            self.signing_key = config.secret_key_input

        # Derive and store public key representations
        self.public_key_obj_ = self.signing_key.public_key() # Store the object for potential other uses

        if self.algorithm == 'EdDSA':
            if not isinstance(self.public_key_obj_, ed25519.Ed25519PublicKey):
                raise ValueError("Internal error: Public key is not an Ed25519PublicKey for EdDSA.")
            # For EdDSA, public_key_serial remains the hex of raw bytes.
            # PoW will use this hex string.
            self.public_key_serial = self.public_key_obj_.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ).hex()
            self.public_key_pem_ = None # Not standard for EdDSA raw public keys
            self.public_key_jwk_ = None # EdDSA JWKs are possible but not primary focus for this step

        elif self.algorithm == 'RSA':
            if not isinstance(self.public_key_obj_, rsa.RSAPublicKey):
                raise ValueError("Internal error: Public key is not an RSAPublicKey for RSA.")
            # Store PEM format, used for PoW
            self.public_key_pem_ = self.public_key_obj_.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            # Store JWK format
            self.public_key_jwk_ = pem_to_jwk(self.public_key_pem_)
            # For 'sub' field and general identification, current example uses public_key_serial.
            # Let's keep public_key_serial as PEM for RSA for now to minimize changes to token creation/validation logic
            # in this step. Next step will transition 'sub' to use JWK representation if desired.
            self.public_key_serial = self.public_key_pem_
        else:
            raise ValueError(f"Unsupported algorithm for public key serialization: {self.algorithm}")

        self.credit = 0

    def get_public_jwk(self) -> dict | None:
        """Returns the public key in JWK format (primarily for RSA)."""
        if self.algorithm == 'RSA':
            return self.public_key_jwk_
        return None # Or raise error, or return specific EdDSA JWK if implemented

    def get_public_pem(self) -> str | None:
        """Returns the public key in PEM format (primarily for RSA)."""
        if self.algorithm == 'RSA':
            return self.public_key_pem_
        return None # EdDSA typically uses raw hex, not PEM for public key id

    def _calculate_score(self, data_to_hash: str) -> tuple[int, str]:
        """Helper function to calculate score from hash."""
        hash_value = hashlib.sha256(data_to_hash.encode()).hexdigest()
        score = 0
        for char in hash_value:
            if char == '0':
                score += 1
            else:
                break
        return score, hash_value


    def generate_slip(self, block_iso_string: str, state_jwt: str | None, target_score: int, max_iterations: int = 1000000) -> dict :
        """
        Generates a slip by performing hashing until a target score is met or max_iterations are reached.

        Args:
            block_iso_string: ISO format string for the block timestamp.
            state_jwt: The JWT string of the previous server state, or None.
            target_score: The minimum PoW score to achieve.
            max_iterations: Maximum number of hashing attempts.

        Returns:
            A dictionary representing the slip if a solution meeting target_score is found.

        Raises:
            Exception: If no solution meeting target_score is found within max_iterations.
        """
        key_for_pow = ""
        if self.algorithm == 'RSA':
            key_for_pow = self.public_key_pem_
        elif self.algorithm == 'EdDSA':
            key_for_pow = self.public_key_serial
        else:
            raise ValueError(f"Unsupported algorithm for PoW: {self.algorithm}")

        if not key_for_pow: # Should not happen if __init__ is correct
             raise ValueError("Public key for PoW is not available.")

        state_jwt_or_empty = state_jwt if state_jwt is not None else ""

        best_slip_so_far = {'score': -1} # Holds the best slip found that might be below target

        for i in range(max_iterations):
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            data_to_hash = f"{key_for_pow}{block_iso_string}{state_jwt_or_empty}{nonce}"
            score, hash_value = self._calculate_score(data_to_hash)

            if score > best_slip_so_far['score']: # Found a new best
                 best_slip_so_far = {
                    'score': score,
                    'nonce': nonce,
                    'hash': hash_value,
                    'start_time': block_iso_string, # Key expected by create_token
                    'public_key_for_pow': key_for_pow, # For potential server-side reconstruction if needed
                    'algorithm': self.algorithm
                }

            if score >= target_score:
                return best_slip_so_far # Return as soon as target is met

        # Loop finished. Check if any valid slip (even if below target) was found.
        if best_slip_so_far['score'] >= 0: # Found at least one hash with score >= 0
            # As per current plan, we return even if below target, server validates.
            # This matches JS SDK behavior where PoW can return a hash below target.
            # Add iterations_taken to the returned slip details
            best_slip_so_far['iterations_taken'] = i + 1
            return best_slip_so_far
        else: # No hash found with score >= 0 or max_iterations reached without any valid hash
            raise Exception(f"Proof-of-Work failed to find any solution (score >= 0) within {max_iterations} iterations.")

    def generate_signed_slip(self, block_iso_string: str, state_jwt: str | None, create: bool, target_score: int | None = None, max_iterations: int | None = None) -> dict:
        """
        Generates a slip and then creates a signed JWT token for it.
        """
        eff_target_score = target_score if target_score is not None else self.default_target_score
        eff_max_iterations = max_iterations if max_iterations is not None else self.default_max_pow_iterations

        slip_details = self.generate_slip(block_iso_string, state_jwt, eff_target_score, eff_max_iterations)

        # create_token expects 'start_time' in slip_details, which generate_slip provides.
        token_jwt = self.create_token(slip_details, state_jwt, create)

        return {
            'slip_payload_for_jwt': { # Reflects what create_token now uses as its core payload
                'publicKey': self.get_public_jwk() if self.algorithm == 'RSA' else self.public_key_serial,
                'block': slip_details['start_time'],
                'nonce': slip_details['nonce'],
                'state': state_jwt,
                'create': create
            },
            'pow_details': {
                'score': slip_details['score'],
                'hash': slip_details['hash'],
                'nonce': slip_details['nonce'],
                'iterations_taken': slip_details.get('iterations_taken')
            },
            'token': token_jwt,
            'client_public_key_pem_for_pow': slip_details['public_key_for_pow']
        }

    def create_token(self, slip: dict, state_jwt: str | None, create: bool = False) -> str:
        """
        Creates a JWT token containing specified slip claims.

        Args:
            slip: The slip dictionary (must contain 'start_time', 'nonce').
            state_jwt: The JWT string of the previous server state, or None if 'create' is True.
            create: A flag indicating if this is a creation token.

        Returns:
            A JWT string.
        """
        if not slip or 'start_time' not in slip or 'nonce' not in slip:
            raise ValueError("Invalid slip object: must contain 'start_time' and 'nonce'.")

        block_timestamp = slip.get('start_time')
        nonce = slip.get('nonce')

        payload = {
            'iat': datetime.datetime.now(datetime.timezone.utc),
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60), # Token expires in 60 seconds
            # 'sub' claim is removed as per new structure
            'block': block_timestamp,
            'nonce': nonce,
            'state': state_jwt,
            'create': create,
            # Other slip components like score, hash are part of the 'slip' dict in the old model,
            # but now are top-level or sourced from the 'slip' input parameter directly.
            # The server will recalculate score and hash based on block, nonce, and publicKey.
        }

        if self.algorithm == 'RSA':
            payload['publicKey'] = self.get_public_jwk()
        else: # EdDSA or other
            payload['publicKey'] = self.public_key_serial # Hex string for EdDSA for now

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
    def __init__(self, config: SlipkeyServerConfig):
        """
        Initializes the SlipkeyServer.

        Args:
            config: Configuration object for the server.
        """
        self.config = config
        self.algorithm = config.algorithm
        self.default_state_token_expiration_seconds = config.default_state_token_expiration_seconds
        self.default_expected_target_score = config.default_expected_target_score

        if config.custom_credit_calculator is None:
            self.credit_calculator = self._default_calculate_credit
        else:
            self.credit_calculator = config.custom_credit_calculator

        if config.secret_key_input is None:
            self.signing_key = generate_secret_key(self.algorithm)
        elif isinstance(config.secret_key_input, str):
            if self.algorithm == 'EdDSA':
                try:
                    private_key_bytes = bytes.fromhex(config.secret_key_input)
                    self.signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                except ValueError as e:
                    raise ValueError(f"Invalid hex secret key format for EdDSA server key: {e}")
            elif self.algorithm == 'RSA':
                try:
                    self.signing_key = serialization.load_pem_private_key(
                        config.secret_key_input.encode(),
                        password=None
                    )
                    if not isinstance(self.signing_key, rsa.RSAPrivateKey):
                         raise ValueError("PEM data did not yield an RSA private key for server.")
                except Exception as e:
                    raise ValueError(f"Invalid PEM secret key format for RSA server key: {e}")
            else:
                raise ValueError(f"Unsupported server algorithm: {self.algorithm}")
        else: # Assuming key object
            if self.algorithm == 'EdDSA' and not isinstance(config.secret_key_input, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided server key is not an Ed25519PrivateKey.")
            elif self.algorithm == 'RSA' and not isinstance(config.secret_key_input, rsa.RSAPrivateKey):
                raise ValueError("Provided server key is not an RSAPrivateKey.")
            self.signing_key = config.secret_key_input

        # Server's public key representations
        self.public_key_obj_ = self.signing_key.public_key()

        if self.algorithm == 'EdDSA':
            if not isinstance(self.public_key_obj_, ed25519.Ed25519PublicKey):
                raise ValueError("Internal error: Server public key is not an Ed25519PublicKey for EdDSA.")
            self.public_key_serial = self.public_key_obj_.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ).hex()
            self.public_key_pem_ = None
            self.public_key_jwk_ = None
        elif self.algorithm == 'RSA':
            if not isinstance(self.public_key_obj_, rsa.RSAPublicKey):
                raise ValueError("Internal error: Server public key is not an RSAPublicKey for RSA.")
            self.public_key_pem_ = self.public_key_obj_.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            self.public_key_jwk_ = pem_to_jwk(self.public_key_pem_)
            # public_key_serial used for 'sub' in server's own state tokens.
            # Consistent with client, using PEM for now.
            self.public_key_serial = self.public_key_pem_
        else:
            raise ValueError(f"Unsupported algorithm for server public key: {self.algorithm}")

        # In-memory store for seen nonces to prevent replay attacks for a short window
        # This should be replaced with a more persistent cache (e.g., Redis) in production
        self.seen_nonces = {} # Store as {nonce: timestamp}
        self.nonce_expiry_seconds = 300 # Nonces expire after 5 minutes

    def _default_calculate_credit(self, metadata: ServerCreditMetadata) -> float | int:
        """Default credit calculation logic."""
        if metadata.is_below_target_score:
            # No credit earned if score is below the expected target, but still valid PoW > 0
            # This means the state is updated (nonce consumed, chain length might increment), but credit doesn't increase.
            return metadata.previous_credit
        # Example: score * 10 (base value for score) + chain_length (bonus for longer chains)
        return metadata.previous_credit + (metadata.pow_score * 10) + metadata.chain_length

    def _determine_client_algorithm_from_pk_claim(self, public_key_claim_value: str | dict) -> str:
        """Helper to determine client algorithm from the publicKey claim."""
        if isinstance(public_key_claim_value, dict): # JWK
            kty = public_key_claim_value.get('kty')
            if kty == 'RSA':
                return 'RSA'
            # Add other kty mappings if needed (e.g., 'OKP' for EdDSA JWK)
            raise ValueError(f"Unsupported JWK 'kty': {kty}")
        elif isinstance(public_key_claim_value, str): # Hex string (assumed EdDSA for now)
            # This is a simplification. A more robust system might require an explicit 'alg' claim
            # alongside a raw public key string, or rely on prior registration of key type.
            # For now, string means EdDSA.
            return 'EdDSA'
        else:
            raise ValueError("Invalid format for publicKey claim.")

    def _verify_and_decode_client_token(self, token: str, client_public_key_claim_value: str | dict, client_algorithm: str) -> dict:
        """
        Verifies and decodes a token using the client's public key (JWK dict for RSA, hex string for EdDSA).
        """
        try:
            verifying_key_obj = None
            jwt_algo_to_check = client_algorithm # Default to client_algorithm (e.g., "EdDSA")

            if client_algorithm == 'RSA':
                if not isinstance(client_public_key_claim_value, dict):
                    raise ValueError("client_public_key_claim_value must be a JWK dictionary for RSA.")
                # Convert JWK to PEM, then load into cryptography key object
                client_public_key_pem = jwk_to_pem(client_public_key_claim_value)
                verifying_key_obj = serialization.load_pem_public_key(client_public_key_pem.encode())
                if not isinstance(verifying_key_obj, rsa.RSAPublicKey):
                    raise ValueError("Client public key JWK did not yield a valid RSA PEM.")
                jwt_algo_to_check = 'RS256' # PyJWT uses 'RS256' for RSA
            elif client_algorithm == 'EdDSA':
                if not isinstance(client_public_key_claim_value, str):
                    raise ValueError("client_public_key_claim_value must be a hex string for EdDSA.")
                public_key_bytes = bytes.fromhex(client_public_key_claim_value)
                verifying_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                # PyJWT uses "EdDSA" for this algorithm name
            else:
                raise ValueError(f"Unsupported client algorithm for token verification: {client_algorithm}")

            if verifying_key_obj is None:
                 raise ValueError("Could not derive verification key.")

            payload = jwt.decode(token, verifying_key_obj, algorithms=[jwt_algo_to_check])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Client token has expired.")
        except jwt.InvalidSignatureError:
            raise ValueError("Client token signature is invalid.")
        except Exception as e:
            raise ValueError(f"Client token decoding/verification failed: {e}")

    def get_public_jwk(self) -> dict | None:
        """Returns the server's public key in JWK format (primarily for RSA)."""
        if self.algorithm == 'RSA':
            return self.public_key_jwk_
        return None

    def get_public_pem(self) -> str | None:
        """Returns the server's public key in PEM format (primarily for RSA)."""
        if self.algorithm == 'RSA':
            return self.public_key_pem_
        return None

    def _calculate_score(self, data_to_hash: str) -> tuple[int, str]:
        """Helper function to calculate score from hash."""
        hash_value = hashlib.sha256(data_to_hash.encode()).hexdigest()
        score = 0
        for char in hash_value:
            if char == '0':
                score += 1
            else:
                break
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

    def process_client_token(self, token: str, expected_target_score: int | None = None) -> tuple[dict | None, str | None]:
        """
        Processes and validates a client's slip JWT.
        This was formerly validate_slip.

        Args:
            token: The slip JWT from the client.
            expected_target_score: Optional; if provided, overrides server's default_expected_target_score for this validation.

        Returns:
            A tuple containing block information and None for error,
            or None and an error message if validation fails.
        """
        self._cleanup_expired_nonces()
        try:
            # 1. Decode token without signature verification to get claims needed for verification key
            # Ensure datetime is available for time_solved, and timezone for UTC
            # from datetime import datetime, timezone (should be at top level)

            unverified_payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_iat": False, "verify_nbf": False})

            client_pk_claim_value = unverified_payload.get('publicKey')
            if not client_pk_claim_value:
                return None, "Missing 'publicKey' claim in token."

            client_algorithm_for_verification = self._determine_client_algorithm_from_pk_claim(client_pk_claim_value)

            client_public_key_for_pow_and_sub = ""
            if client_algorithm_for_verification == 'RSA':
                if not isinstance(client_pk_claim_value, dict):
                     return None, "publicKey claim for RSA client should be a JWK dictionary."
                client_public_key_for_pow_and_sub = jwk_to_pem(client_pk_claim_value)
            elif client_algorithm_for_verification == 'EdDSA':
                if not isinstance(client_pk_claim_value, str):
                    return None, "publicKey claim for EdDSA client should be a hex string."
                client_public_key_for_pow_and_sub = client_pk_claim_value
            else:
                return None, f"Unsupported client algorithm derived: {client_algorithm_for_verification}"

            payload = self._verify_and_decode_client_token(token, client_pk_claim_value, client_algorithm_for_verification)

            block_iso_from_payload = payload.get('block') # Renamed from block_timestamp for clarity
            nonce_from_payload = payload.get('nonce')
            is_create = payload.get('create', False)
            client_state_jwt_from_payload = payload.get('state')

            if not isinstance(block_iso_from_payload, str) or not nonce_from_payload: # block should be string (ISO format)
                return None, "Invalid or missing components in token (block ISO string, nonce)."

            # Prevent replay attacks using nonce
            if nonce_from_payload in self.seen_nonces:
                return None, "Replayed nonce. This slip has already been processed."


            # 4. Verify 'block' (start_time) is not in the future (allowing for small clock skew)
            current_server_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
            # Convert block_iso_from_payload to numeric timestamp for comparison
            try:
                block_numeric_timestamp = datetime.datetime.fromisoformat(block_iso_from_payload.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None, f"Invalid block ISO string format: {block_iso_from_payload}"

            if block_numeric_timestamp > current_server_time + 60: # Allow 60s clock skew
                return None, f"Slip 'block' timestamp ({block_iso_from_payload}) is too far in the future."

            # 5. Recalculate hash and verify score
            client_state_jwt_or_empty = client_state_jwt_from_payload if client_state_jwt_from_payload is not None else ""
            data_to_hash = f"{client_public_key_for_pow_and_sub}{block_iso_from_payload}{client_state_jwt_or_empty}{nonce_from_payload}"
            recalculated_score, recalculated_hash = self._calculate_score(data_to_hash)

            actual_expected_target_score = expected_target_score if expected_target_score is not None else self.default_expected_target_score

            if not (recalculated_score > 0): # Basic PoW validity: must have some score
                return None, f"Proof-of-work score ({recalculated_score}) is not sufficient (must be > 0)."

            is_below_target_score = (recalculated_score < actual_expected_target_score)


            # 6. Handle 'create' flag and 'state'
            previous_credit_from_state = 0.0
            previous_len_from_state = 0
            if is_create:
                if client_state_jwt_from_payload is not None:
                    return None, "State must be absent when 'create' flag is True."
            else:
                if client_state_jwt_from_payload is None:
                    return None, "State must be present when 'create' flag is False."
                try:
                    server_verifying_key_for_state = self.signing_key.public_key()
                    jwt_state_algo_to_check = self.algorithm
                    if self.algorithm == 'RSA': jwt_state_algo_to_check = 'RS256'

                    state_payload = jwt.decode(client_state_jwt_from_payload, server_verifying_key_for_state, algorithms=[jwt_state_algo_to_check])

                    if state_payload.get('sub') != client_public_key_for_pow_and_sub:
                        return None, "Client public key (PEM/hex) in state 'sub' does not match current client's derived PEM/hex."
                    if 'publicKey' in state_payload and state_payload.get('publicKey') != client_pk_claim_value:
                        if client_algorithm_for_verification == 'RSA' and isinstance(client_pk_claim_value, dict):
                            if json.dumps(state_payload.get('publicKey'), sort_keys=True) != json.dumps(client_pk_claim_value, sort_keys=True):
                                return None, "Client 'publicKey' (JWK) in state does not match current client's 'publicKey' (JWK)."
                        elif client_algorithm_for_verification == 'EdDSA' and isinstance(client_pk_claim_value, str):
                            if state_payload.get('publicKey') != client_pk_claim_value:
                                 return None, "Client 'publicKey' (hex) in state does not match current client's 'publicKey' (hex)."

                    previous_credit_from_state = state_payload.get('credit', 0.0)
                    previous_len_from_state = state_payload.get('len', 0)

                except jwt.ExpiredSignatureError: return None, "Provided state token has expired."
                except jwt.InvalidTokenError as e: return None, f"Invalid state token: {e}"

            # 7. Calculate credit earned using the configured credit_calculator
            # The 'len' of the new state is based on previous_len_from_state.
            new_chain_length = previous_len_from_state + 1

            metadata = ServerCreditMetadata(
                block_timestamp=block_iso_from_payload,
                time_solved=datetime.datetime.now(datetime.timezone.utc),
                pow_score=recalculated_score,
                chain_length=new_chain_length,
                client_public_key_claim_value=client_pk_claim_value,
                previous_credit=previous_credit_from_state,
                previous_chain_length=previous_len_from_state,
                is_below_target_score=is_below_target_score
            )
            current_total_credit = self.credit_calculator(metadata)
            credit_earned_this_slip = current_total_credit - previous_credit_from_state

            # 8. Generate new state object
            new_block_identifier = block_iso_from_payload
            next_len_suggestion = new_chain_length # Server dictates the chain length in the new state.

            new_state_payload = {
                'iat': int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
                'exp': int(datetime.datetime.now(datetime.timezone.utc).timestamp() + datetime.timedelta(seconds=self.default_state_token_expiration_seconds)),
                'sub': client_public_key_for_pow_and_sub,
                'publicKey': client_pk_claim_value,
                'credit': current_total_credit,
                'block': new_block_identifier,
                'len': next_len_suggestion,
            }

            # 9. Encode new state into a JWT using the server's private key and its algorithm
            jwt_server_state_algorithm = self.algorithm
            if self.algorithm == 'RSA':
                jwt_server_state_algorithm = 'RS256'

            new_state_jwt = jwt.encode(new_state_payload, self.signing_key, algorithm=jwt_server_state_algorithm)

            # Add nonce to seen list after successful processing
            self.seen_nonces[nonce_from_payload] = current_server_time


            # 10. Return block information
            response_data = {
                'block': new_block_identifier,
                'len': next_len_suggestion,
                'state': new_state_jwt,
                'score': recalculated_score,
                'hash': recalculated_hash,
                'expires': new_state_payload['exp'],
                'credit': current_total_credit, # Updated total credit
                'creditEarned': credit_earned_this_slip, # Newly earned credit
                'publicKey': client_pk_claim_value,
                'is_below_target_score': is_below_target_score # Inform client if score was below target
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
