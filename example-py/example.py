import jwt
import hashlib
import click
# from time import sleep # Unused
from datetime import datetime, timedelta, timezone # Added timezone
import random
import string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import json

def generate_secret_key(algorithm='RSA'):
    if algorithm == 'RSA':
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    
    return Exception("Unsupported algorithm")

def serialize_secret_key(secret_key, algorithm='RSA'):
    # Serialize the secret key to PEM format
    if algorithm == 'RSA':
        return secret_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    return Exception("Unsupported algorithm")

def generate_public_key(private_key, algorithm='RSA'):
    # Generate a public key based on the secret key
    if algorithm == 'RSA':
        # Serialize the public key to PEM format
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key.decode('utf-8')
    
    return Exception("Unsupported algorithm")

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

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')

    n_b64url = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')
    e_b64url = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode('utf-8')

    jwk = {
        "kty": "RSA",
        "n": n_b64url,
        "e": e_b64url,
        "alg": "RS256",  # Optional: good to include
        # "use": "sig"    # Optional: if key is for signing/verification
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

class Client:
    def __init__(self, secret_key, algorithm):
        if not secret_key:
            raise ValueError("Secret key is required")
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.public_key = generate_public_key(self.secret_key, algorithm=algorithm)
        self.state = None  # Server state (JWT) from the last solved block

    def generate(self, start_time, block_interval=100, max_interval=10, progress_interval=1, target_score=1, best_slip=None):
        """
        Generate a slip by solving a proof-of-work problem.
        """
        block_ts = (start_time + timedelta(seconds=block_interval)).isoformat()
        nonce = None
        hashes = 0
        block_start_time = datetime.now()
        while True:
            hashes += 1
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            data = f"{self.public_key}{block_ts}{self.state or ''}{nonce}"
            hashed = hashlib.sha256(data.encode()).hexdigest()
            score = len(hashed) - len(hashed.lstrip('0'))
                
            if not best_slip or score > best_slip['score']:
                best_slip = {
                    "block": block_ts,
                    "publicKey": self.public_key,
                    "nonce": nonce,
                    "state": self.state,
                    "score": score,
                    "create": self.state is None
                }

            total_time = (datetime.now() - start_time).total_seconds()
            block_time = (datetime.now() - block_start_time).total_seconds()
            if block_time > progress_interval or total_time > max_interval or (target_score and score >= target_score):
                return best_slip, {
                    "done": (total_time > max_interval) or (target_score and score >= target_score), # Debug
                    "hashes": hashes,
                    "elapsed": total_time
                }
    
    def generate_token(self, slip, create=False):
        """
        Generate a JWT token based on the slip.
        """
        if not slip:
            raise ValueError("Slip is required")
        
        # Create a JWT token with the slip data
        client_public_key_pem = slip['publicKey'] # This is the PEM string from the slip object
        client_public_key_jwk = pem_to_jwk(client_public_key_pem)

        claims = {
            "publicKey": client_public_key_jwk, # Use JWK format for the claim
            "block": slip['block'],
            "nonce": slip['nonce'],
            "state": slip['state'],
            "create": create,
        }
        # print(f"    [Client JWT Claims]: {json.dumps(claims, indent=2)}") # Temporary print removed
        token = jwt.encode(claims, self.secret_key, algorithm="RS256")
        
        return token

    def receive(self, response):
        """
        Receive and process the server's response.
        """
        try:
            self.state = response['state']
            credit = response['credit']
        except KeyError:
            return None, ValueError("Invalid response from server")
        
        if not credit:
            raise ValueError("Invalid response: missing credit")
        if not isinstance(credit, int):
            raise ValueError("Invalid response: credit should be an integer")
        if credit < 0:
            raise ValueError("Invalid response: credit should be non-negative")
        return credit, None

    @classmethod
    def init(cls, secret_key, alg):
        return cls(secret_key, alg)


class Server:
    def __init__(self, secret_key, alg='RSA'):
        if not secret_key:
            raise ValueError("Secret key is required")
        self.algorithm = alg
        self.secret_key = secret_key
        self.public_key = generate_public_key(self.secret_key, algorithm=alg)

    def submit(self, slip):
        """
        Validate the submitted slip and return a new state if valid.
        """

        try:
            # 1. Decode client JWT to get claims, including the client's public key JWK
            unverified_payload = jwt.decode(slip, algorithms=["RS256"], options={"verify_signature": False})

            client_public_key_jwk = unverified_payload.get('publicKey')
            if not client_public_key_jwk or not isinstance(client_public_key_jwk, dict):
                return None, ValueError("Invalid slip: missing or malformed publicKey (JWK).")

            # Convert client's public JWK to PEM for actual signature verification
            # (as PyJWT typically expects PEM or a cryptography key object)
            try:
                client_public_key_pem_for_verify = jwk_to_pem(client_public_key_jwk)
            except Exception as e:
                return None, ValueError(f"Invalid client public key in slip (not a valid JWK): {e}")

            # Verify the client JWT signature using the derived PEM key
            slip_claims = jwt.decode(slip, client_public_key_pem_for_verify, algorithms=["RS256"])

            # Verify the block timestamp is in the future (use UTC for comparison)
            block_time = datetime.fromisoformat(slip_claims['block'].replace('Z', '+00:00'))
            if block_time.tzinfo is None: # Should be ISO string with Z or offset
                 # If no timezone, assume UTC for safety, but ideally client sends tz-aware string
                block_time = block_time.replace(tzinfo=timezone.utc)

            if block_time <= datetime.now(timezone.utc): # Compare with UTC now
                return None, ValueError("Block timestamp is not in the future.")

            # 2. Proof-of-Work Validation (needs client public key in PEM)
            # client_public_key_jwk_from_claims = slip_claims['publicKey'] # This is already a dict (JWK)
            # No need to re-access from slip_claims if client_public_key_pem_for_verify is already the PEM.
            # If it was not, we would do:
            # client_public_key_pem_for_pow = jwk_to_pem(client_public_key_jwk_from_claims)
            client_public_key_pem_for_pow = client_public_key_pem_for_verify

            data_to_hash = f"{client_public_key_pem_for_pow}{slip_claims['block']}{slip_claims.get('state') or ''}{slip_claims['nonce']}"
            hashed = hashlib.sha256(data_to_hash.encode()).hexdigest()
            score = len(hashed) - len(hashed.lstrip('0'))
            if score <= 0:
                return None, ValueError("Invalid proof-of-work solution (score <= 0).")
            
            # Logic for handling 'create' flag and 'state' presence
            is_genesis = slip_claims.get('create', False)
            state_jwt_from_client = slip_claims.get('state')

            if is_genesis and state_jwt_from_client is not None:
                return None, ValueError("Invalid slip: 'create' is true but 'state' is present.")
            if not is_genesis and state_jwt_from_client is None:
                return None, ValueError("Invalid slip: 'create' is false but 'state' is missing.")

            previous_credit = 0
            previous_len = 0
            decoded_state_payload = None # To hold payload of previous server state

            if state_jwt_from_client:
                # 3. Verify Previous Server state JWT (including expiration)
                # PyJWT decode automatically checks 'exp' if present in the token.
                # self.public_key is the server's PEM public key.
                try:
                    decoded_state_payload = jwt.decode(state_jwt_from_client, self.public_key, algorithms=["RS256"])
                except jwt.ExpiredSignatureError:
                    return None, ValueError("Previous server state (JWT) has expired.")
                except jwt.InvalidTokenError as e:
                    return None, ValueError(f"Previous server state (JWT) is invalid: {e}")

                # Validate that the public key in the previous state matches the client's current public key
                # The 'publicKey' in the old state JWT should also be a JWK if we follow the new convention.
                # For now, assuming it might be old format (PEM) or needs careful check.
                # For this update, let's assume the server always issued JWKs for 'publicKey' in its state.
                prev_state_client_jwk = decoded_state_payload.get('publicKey')
                if not prev_state_client_jwk or not isinstance(prev_state_client_jwk, dict):
                     return None, ValueError("Invalid 'publicKey' (JWK) in previous server state.")
                
                # Compare essential fields of JWKs (n and e for RSA)
                if (prev_state_client_jwk.get('n') != client_public_key_jwk.get('n') or
                    prev_state_client_jwk.get('e') != client_public_key_jwk.get('e') or
                    prev_state_client_jwk.get('kty') != client_public_key_jwk.get('kty')):
                    return None, ValueError("Client public key in current slip does not match 'publicKey' in previous server state.")

                previous_credit = decoded_state_payload.get('credit', 0)
                previous_len = decoded_state_payload.get('len', 0)

            # Calculate the credit earned
            credit_earned_this_slip = 2 * score # Example: server's scoring logic

            # 4. Issue New Server State JWT
            issue_ts_utc = datetime.now(timezone.utc)
            expiration_ts_utc = issue_ts_utc + timedelta(days=7) # Example: 7 days validity

            new_server_state_payload = {
                "iat": int(issue_ts_utc.timestamp()),
                "exp": int(expiration_ts_utc.timestamp()),
                "sub": json.dumps(client_public_key_jwk, sort_keys=True), # Subject is stringified client JWK
                "publicKey": client_public_key_jwk, # Client's public key as JWK
                "credit": previous_credit + credit_earned_this_slip,
                "block": slip_claims['block'],
                "len": previous_len + 1
            }

            # Encode the new state into a JWT using server's private key
            # print(f"    [Server State JWT Payload]: {json.dumps(new_server_state_payload, indent=2)}") # Temporary print removed
            new_state_jwt = jwt.encode(new_server_state_payload, self.secret_key, algorithm="RS256")

            return {
                "block": new_server_state_payload['block'],
                "len": new_server_state_payload['len'],
                "state": new_state_jwt,
                "score": score, # PoW score of the *current* slip
                "expires": new_server_state_payload['exp'], # Expiration of the *new* state token
                "credit": new_server_state_payload['credit'], # Total credit
                "creditEarned": credit_earned_this_slip, # Credit earned from this specific slip
            }, None
        except jwt.ExpiredSignatureError:
            return None, ValueError("JWT has expired")
        except jwt.InvalidTokenError:
            return None, ValueError("Invalid JWT token")
        except Exception as e:
            return None, e

    @classmethod
    def init(cls, secret_key, alg):
        return cls(secret_key, alg)

CLIENT = 'Client'
SERVER = 'Server'
def log(who, message, indent=0):
    output = f'{message}'
    if indent > 0:
        output = ' ' * indent + message
    else:
        output = f'[{who}] {message}'
    print(output)

MAX_INTERVAL = 1 # Seconds
PROGRESS_INTERVAL = 0.5 # Seconds

@click.command()
@click.option('--client-secret-key', default=None, help='Secret key of client for JWT encoding/decoding')
@click.option('--server-secret-key', default=None, help='Secret key of server for JWT encoding/decoding')
@click.option('--algorithm', default='RSA', help='Algorithm for JWT encoding/decoding')
@click.option('--progress-interval', default=PROGRESS_INTERVAL, help='Interval for progress updates')
@click.option('--max-interval', default=MAX_INTERVAL, help='Interval for progress updates')
@click.option('--target-score', default=1, help='Target score for proof-of-work')
@click.option('--target-credit', default=10, help='Target credit earned')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def main(client_secret_key, server_secret_key, algorithm, progress_interval, max_interval, target_score, target_credit, verbose):
    """
    Example function to demonstrate JWT encoding/decoding.
    """
    # Create a client and server instance
    if not client_secret_key:
        client_secret_key = generate_secret_key(algorithm=algorithm)
        log(CLIENT, f"Client secret key generated")
    if not server_secret_key:
        server_secret_key = generate_secret_key(algorithm=algorithm)
        log(SERVER, f"Server secret key generated")

    client = Client.init(secret_key=client_secret_key, alg=algorithm)
    server = Server.init(secret_key=server_secret_key, alg=algorithm)

    credit = 0
    slip = None
    generation_start_time = datetime.now()
    created = False

    def elapsed_time():
        return (datetime.now() - generation_start_time)

    while credit < target_credit:
        log(CLIENT, "Generating slip...")
        progress = {}
        interval = 1
        block_start_time = datetime.now()
        while progress.get('done', False) is False:
            # Generate a slip
            slip, progress = client.generate(block_start_time, block_interval=2*max_interval, max_interval=max_interval, progress_interval=progress_interval, target_score=target_score, best_slip=slip)
            print(f"[{interval}] {progress['hashes']:08} hashes, Score={slip['score'] if slip else 0}, {max(max_interval - elapsed_time().total_seconds(), 0)} remaining")
            interval += 1

        if not slip:
            log(CLIENT, "Failed to generate slip. Retrying with new block")
            continue

        log(CLIENT, f"Slip ({slip['nonce']}) generated with score={slip['score']} in {elapsed_time().total_seconds():.2f} seconds")

        token = client.generate_token(slip, create=not created)

        res, err = server.submit(token)
        if err:
            raise err
        
        log(SERVER, f"Slip accepted")
        log(SERVER, f"Credit={res['credit']}, Block={res['block']}, Len={res['len']}")
        
        credit, err = client.receive(res)
        if err:
            raise err
        
        log(CLIENT, f"Credit={credit}")

        generation_start_time = datetime.now()
        created = True
        slip = None


def run_conversion_tests():
    print("\n--- Running PEM-JWK Conversion Tests ---")

    # 1. Generate a sample RSA key pair
    private_key_obj = generate_secret_key(algorithm='RSA')
    original_pem_public_key = generate_public_key(private_key_obj, algorithm='RSA')

    print(f"Original PEM Public Key:\n{original_pem_public_key}")

    # 2. Convert PEM to JWK
    try:
        jwk_output = pem_to_jwk(original_pem_public_key)
        print(f"Converted JWK:\n{json.dumps(jwk_output, indent=2)}")
    except Exception as e:
        print(f"Error during PEM to JWK conversion: {e}")
        return

    # 3. Convert JWK back to PEM
    try:
        reconstructed_pem_public_key = jwk_to_pem(jwk_output)
        print(f"Reconstructed PEM Public Key:\n{reconstructed_pem_public_key}")
    except Exception as e:
        print(f"Error during JWK to PEM conversion: {e}")
        return

    # 4. Verify
    assert original_pem_public_key.strip() == reconstructed_pem_public_key.strip(), \
        "PEM->JWK->PEM conversion failed: Reconstructed PEM does not match original."
    print("PEM -> JWK -> PEM conversion successful!")
    print("--- Conversion Tests Complete ---\n")

if __name__ == '__main__':
    run_conversion_tests()
    main()