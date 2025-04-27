import jwt
import hashlib
import click
from time import sleep
import datetime

class Client:
    # TODO: Implement the Client class with methods for generating slips and receiving results
    pass

class Server:
    # TODO: Implement the Server class with methods for submitting slips and returning results
    pass

CLIENT = 'Client'
SERVER = 'Server'
def log(who, message, indent=0):
    output = f'{message}'
    if indent > 0:
        output = ' ' * indent + message
    else:
        output = f'[{who}] {message}'
    print(output)

PROGRESS_INTERVAL = 0.1

@click.command()
@click.option('--client-secret-key', default=None, help='Secret key of client for JWT encoding/decoding')
@click.option('--server-secret-key', default=None, help='Secret key of server for JWT encoding/decoding')
@click.option('--algorithm', default='RSA', help='Algorithm for JWT encoding/decoding')
def main(client_secret_key, server_secret_key, algorithm):
    """
    Example function to demonstrate JWT encoding/decoding.
    """
    # Create a client and server instance
    client = Client.init(secret_key=client_secret_key, alg=algorithm)
    server = Server.init(secret_key=server_secret_key)

    slip = None
    generation_start_time = datetime.now()
    while slip is None:
        log(CLIENT, "Generating slip...")
        progress = {}
        while progress.get('done', False) is False:
            # Generate a slip
            slip, progress = client.generate(progress_interval=PROGRESS_INTERVAL)
            print(f"[{progress.iterations}] {progress.hashes:08} hashes")

        if not slip:
            log(CLIENT, "Failed to generate slip.")
            continue

        log(CLIENT, f"Slip generated score={progress.max_score} in {progress.iterations} iterations")
        log(CLIENT, f"Total time={progress.total_time:.2f} seconds")

        res, err = server.submit(slip)
        if err:
            raise err
        
        log(SERVER, f"Slip accepted")
        log(SERVER, f"Credit={res.credit}, Block={res.block}, Len={res.len}")
        
        err = client.receive(res)
        if err:
            raise err

        sleep(1)
        generation_start_time = datetime.now()