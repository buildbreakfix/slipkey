import jwt
import hashlib
import click
from time import sleep
from datetime import datetime, timedelta
import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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
        token = jwt.encode({
            "publicKey": slip['publicKey'],
            "block": slip['block'],
            "nonce": slip['nonce'],
            "state": slip['state'],
            "create": create,
        }, self.secret_key, algorithm="RS256")
        
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
            # Extract public key from the slip
            unverfieid_slip = jwt.decode(slip, algorithms=["RS256"], options={"verify_signature": False})
            public_key = unverfieid_slip.get('publicKey', None)
            if not public_key:
                return None, ValueError("Invalid slip: missing public key")

            # Verify the slip signature
            slip_claims = jwt.decode(slip, public_key, algorithms=["RS256"])

            # Verify the block timestamp is in the future
            block_time = datetime.fromisoformat(slip_claims['block'])
            if block_time <= datetime.now():
                return None, ValueError("Block timestamp is not in the future")

            # Verify the proof-of-work solution
            data = f"{slip_claims['publicKey']}{slip_claims['block']}{slip_claims.get('state') or ''}{slip_claims['nonce']}"
            hashed = hashlib.sha256(data.encode()).hexdigest()
            score = len(hashed) - len(hashed.lstrip('0'))
            if score <= 0:
                return None, ValueError("Invalid proof-of-work solution")
            
            credit = 0
            decoded_state = None
            state = slip_claims.get('state', None)

            if slip_claims.get('create', False) and state:
                # If creating a new slip, state should be None
                return None, ValueError("Invalid slip: should not contain state")
            
            if not slip_claims.get('create', False) and not state:
                # If not creating a new slip, state should be present
                return None, ValueError("Invalid slip: missing state")

            if state:
                # Decode the existing state
                decoded_state = jwt.decode(state, self.public_key, algorithms=["RS256"])
                if decoded_state['publicKey'] != slip_claims['publicKey']:
                    return None, ValueError("Invalid state: public key mismatch")
                
                credit = decoded_state['credit']

            # Calculate the credit earned
            credit_earned = 2*score

            # Generate a new JWT state
            issue_ts = datetime.now()
            self.state = {
                "iat": int(issue_ts.timestamp()),
                "publicKey": slip_claims['publicKey'],
                "credit": credit + credit_earned,
                "block": slip_claims['block'],
                "len": (decoded_state['len'] + 1) if decoded_state else 1
            }

            # Encode the new state into a JWT
            new_state = jwt.encode(self.state, self.secret_key, algorithm="RS256")

            return {
                "block": self.state['block'], 
                "len": self.state['len'],   
                "state": new_state, 
                "score": score,
                "expires": (issue_ts + timedelta(days=100*365)).timestamp(),
                "credit": self.state['credit'],
                "creditEarned": credit_earned,
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


if __name__ == '__main__':
    main()