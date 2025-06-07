import click
from datetime import datetime, timezone, timedelta
from slipkey_sdk.slipkey import SlipkeyClient, SlipkeyServer, SlipkeyClientConfig, SlipkeyServerConfig, generate_secret_key, ServerCreditMetadata # Import ServerCreditMetadata

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
@click.option('--client-secret-key-input', default=None, help='Secret key of client (hex for EdDSA, PEM string for RSA)')
@click.option('--server-secret-key-input', default=None, help='Secret key of server (hex for EdDSA, PEM string for RSA)')
@click.option('--algorithm', default='RSA', help='Algorithm for keys and signing (RSA or EdDSA)') # Defaulting to RSA
# progress_interval and max_interval are no longer directly used by client.generate_slip
# They could be repurposed for a UI progress display or removed.
# @click.option('--progress-interval', default=PROGRESS_INTERVAL, help='Interval for progress updates during slip generation (seconds)')
# @click.option('--max-interval', default=MAX_INTERVAL, help='Maximum time to spend on generating a single slip (seconds)')
@click.option('--target-score', default=1, type=int, help='Target score for proof-of-work')
@click.option('--max-pow-iterations', default=1000000, type=int, help='Max iterations for client PoW')
@click.option('--target-credit', default=10, type=int, help='Target credit earned by the client')
@click.option('--verbose', is_flag=True, help='Enable verbose output') # verbose is not currently used
def main(client_secret_key_input, server_secret_key_input, algorithm, target_score, max_pow_iterations, target_credit, verbose):
    """
    Example function to demonstrate Slipkey client-server interaction.
    """
    # Create a client and server instance
    # For EdDSA, keys are hex strings. For RSA, they are PEM strings.
    # The SDK handles the distinction based on the 'algorithm' parameter.

    # Config creation
    actual_client_key_input = client_secret_key_input
    if not client_secret_key_input:
        actual_client_key_input = generate_secret_key(algorithm=algorithm)
        log(CLIENT, "Client secret key generated.")
    else:
        log(CLIENT, "Client secret key provided.")

    client_config = SlipkeyClientConfig(
        secret_key_input=actual_client_key_input,
        algorithm=algorithm,
        default_target_score=target_score, # Using CLI's target_score as default
        default_max_pow_iterations=max_pow_iterations # Using CLI's max_pow_iterations as default
    )

    actual_server_key_input = server_secret_key_input
    if not server_secret_key_input:
        actual_server_key_input = generate_secret_key(algorithm=algorithm)
        log(SERVER, "Server secret key generated.")
    else:
        log(SERVER, "Server secret key provided.")

    # Example custom credit calculator (optional, for demonstration)
    # def my_custom_credit_calc(metadata: ServerCreditMetadata) -> int:
    #     log("SERVER", f"Custom credit calc called. Prev credit: {metadata.previous_credit}, Score: {metadata.pow_score}, Below Target: {metadata.is_below_target_score}")
    #     if metadata.is_below_target_score:
    #         return metadata.previous_credit # No credit if below target
    #     # Award 5 points per score unit, plus 1 for chain length
    #     return metadata.previous_credit + (metadata.pow_score * 5) + metadata.chain_length

    server_config = SlipkeyServerConfig(
        secret_key_input=actual_server_key_input,
        algorithm=algorithm,
        default_expected_target_score=target_score # Server also knows the target
        # custom_credit_calculator=my_custom_credit_calc # Uncomment to use custom calculator
    )

    try:
        client = SlipkeyClient(config=client_config)
        # Log relevant part of public key (PEM for RSA, hex for EdDSA)
        pk_display = client.public_key_pem_[:30] if client.algorithm == 'RSA' else client.public_key_serial[:30]
        log(CLIENT, f"Client initialized with {client.algorithm}. Public Key: {pk_display}...")

        server = SlipkeyServer(config=server_config)
        pk_display_server = server.public_key_pem_[:30] if server.algorithm == 'RSA' else server.public_key_serial[:30]
        log(SERVER, f"Server initialized with {server.algorithm}. Public Key: {pk_display_server}...")
    except ValueError as e:
        log("SETUP", f"Error initializing client or server: {e}")
        return

    current_credit = 0
    best_slip_found = None # Stores the best slip from the client's perspective
    client_has_valid_state = False # Tracks if client has a state from server
    # This will store the actual state JWT string from the server for the client to use
    current_server_state_jwt_for_client = None
    # max_pow_iterations is now part of client_config.default_max_pow_iterations or passed to generate_signed_slip


    # Main loop: client generates slips, server validates them
    loop_count = 0
    while current_credit < target_credit:
        loop_count += 1
        log(CLIENT, f"--- Loop {loop_count}: Current Credit = {current_credit}, Target = {target_credit} ---")

        # 1. Client generates a signed slip (PoW + JWT creation)
        log(CLIENT, "Attempting to generate a signed slip...")

        block_future_seconds = 60
        block_datetime = datetime.now(timezone.utc) + timedelta(seconds=block_future_seconds)
        block_iso_string = block_datetime.isoformat()

        log(CLIENT, f"Targeting block ISO string: {block_iso_string} with target score: {target_score}")

        try:
            signed_slip_result = client.generate_signed_slip(
                block_iso_string=block_iso_string,
                state_jwt=current_server_state_jwt_for_client,
                create=not client_has_valid_state, # True if no valid state yet
                target_score=target_score, # from CLI, passed to client_config.default_target_score
                max_iterations=max_pow_iterations # from CLI, passed to client_config.default_max_pow_iterations
            )
            token = signed_slip_result['token']
            pow_details = signed_slip_result['pow_details']
            log(CLIENT, f"Signed slip generated. Token: {token[:50]}...")
            log(CLIENT, f"  PoW details: Score={pow_details['score']}, Iterations={pow_details.get('iterations_taken', 'N/A')}, Hash={pow_details['hash'][:10]}...")

            if pow_details['score'] < target_score:
                 log(CLIENT, f"  WARNING: Slip score {pow_details['score']} is less than target {target_score}. Server might reject.")

        except Exception as e:
            log(CLIENT, f"Error generating signed slip: {e}")
            break

        # 2. Client submits token to Server (No separate create_token step here)

        # 3. Server processes the client's token
        log(SERVER, f"Server received token for processing...")
        validation_response, error_message = server.process_client_token(token)

        if error_message:
            log(SERVER, f"Slip validation failed: {error_message}")
            if "replayed nonce" in error_message.lower() or "invalid state" in error_message.lower() or "state must be present" in error_message.lower():
                client_has_valid_state = False
                current_server_state_jwt_for_client = None # Clear stored state
            # No continue here, let client process this error via response
        else:
            log(SERVER, "Slip validated successfully!")
            log(SERVER, f"  Response: Credit={validation_response['credit']:.2f}, Earned={validation_response['creditEarned']:.2f}, Score={validation_response['score']:.2f}, BelowTarget={validation_response.get('is_below_target_score', 'N/A')}")
            log(SERVER, f"  New state for client: {validation_response['state'][:50]}...")

        # 4. Client processes server's response
        # The client.process_response updates its internal credit.
        # It needs the full validation_response dictionary if successful, or an error dict.
        response_for_client = validation_response if not error_message else {"error": error_message}
        processed_credit, client_error_message = client.process_response(response_for_client)

        if client_error_message: # This is error from client's perspective AFTER processing
            log(CLIENT, f"Client processing error: {client_error_message}")
            # If server rejected the slip, client's credit remains unchanged.
            # If the error implies the state is bad, reset it.
            if "invalid state" in client_error_message.lower() or (validation_response and "state" not in validation_response):
                 client_has_valid_state = False
                 current_server_state_jwt_for_client = None
        else:
            current_credit = processed_credit
            log(CLIENT, f"Successfully processed server response. Current Credit = {current_credit:.2f}")
            # If successful and server sent back a state, store it for next round
            if validation_response and 'state' in validation_response:
                client_has_valid_state = True
                current_server_state_jwt_for_client = validation_response['state']
            else: # Server accepted slip but didn't return state (e.g. error occurred after validation but before state gen)
                client_has_valid_state = False
                current_server_state_jwt_for_client = None


        if current_credit >= target_credit:
            log("MAIN", f"Target credit of {target_credit} reached. Final credit: {current_credit:.2f}")
            break
        # Safety break conditions
        if loop_count > (target_credit * 5 + 10) : # Adjusted safety break
            log("MAIN", f"Too many loops ({loop_count}) without reaching target credit. Exiting.")
            break

    log("MAIN", "Example finished.")

if __name__ == '__main__':
    main()