import unittest
import time # For simulating time progression
import datetime
from slipkey_sdk.slipkey import (
    SlipkeyClient,
    SlipkeyServer,
    generate_secret_key,
    serialize_secret_key,
    generate_public_key
)
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
import jwt # For inspecting tokens

class TestSlipkeySDK(unittest.TestCase):

    def _test_key_utilities_for_algo(self, algorithm):
        # Test generate_secret_key
        sk1 = generate_secret_key(algorithm=algorithm)
        self.assertIsNotNone(sk1)
        if algorithm == 'EdDSA':
            self.assertIsInstance(sk1, ed25519.Ed25519PrivateKey)
        elif algorithm == 'RSA':
            self.assertIsInstance(sk1, rsa.RSAPrivateKey)

        # Test serialize_secret_key
        serialized_sk1 = serialize_secret_key(sk1, algorithm=algorithm)
        self.assertIsNotNone(serialized_sk1)
        if algorithm == 'EdDSA':
            self.assertIsInstance(serialized_sk1, str) # Hex string
            # Try to load it back
            sk1_reloaded = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(serialized_sk1))
            self.assertIsNotNone(sk1_reloaded)
        elif algorithm == 'RSA':
            self.assertIsInstance(serialized_sk1, bytes) # PEM bytes
             # Try to load it back
            sk1_reloaded = serialization.load_pem_private_key(serialized_sk1, password=None)
            self.assertIsNotNone(sk1_reloaded)


        # Test generate_public_key
        pk1_serial = generate_public_key(sk1, algorithm=algorithm)
        self.assertIsNotNone(pk1_serial)

        pk1_obj = sk1.public_key()

        if algorithm == 'EdDSA':
            self.assertIsInstance(pk1_serial, str) # Hex string
            pk1_reloaded_bytes = bytes.fromhex(pk1_serial)
            pk1_reloaded_obj = ed25519.Ed25519PublicKey.from_public_bytes(pk1_reloaded_bytes)
            self.assertEqual(pk1_reloaded_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                             pk1_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        elif algorithm == 'RSA':
            self.assertIsInstance(pk1_serial, bytes) # PEM bytes
            pk1_reloaded_obj = serialization.load_pem_public_key(pk1_serial)
            self.assertEqual(pk1_reloaded_obj.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
                             pk1_obj.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


    def test_key_utilities_eddsa(self):
        self._test_key_utilities_for_algo('EdDSA')

    def test_key_utilities_rsa(self):
        self._test_key_utilities_for_algo('RSA')

    def _test_client_init_for_algo(self, algorithm):
        # Init without key
        client1 = SlipkeyClient(secret_key_input=None, algorithm=algorithm)
        self.assertIsNotNone(client1.signing_key)
        self.assertIsNotNone(client1.public_key_serial)
        self.assertEqual(client1.algorithm, algorithm)

        # Init with generated key object
        sk = generate_secret_key(algorithm=algorithm)
        client2 = SlipkeyClient(secret_key_input=sk, algorithm=algorithm)
        self.assertEqual(client2.signing_key, sk)

        # Init with serialized key
        serialized_sk = serialize_secret_key(sk, algorithm=algorithm)
        client3 = SlipkeyClient(secret_key_input=serialized_sk, algorithm=algorithm)
        self.assertIsNotNone(client3.signing_key)
        # Ensure public keys match (careful with object vs serialized comparison)
        self.assertEqual(client3.public_key_serial, client2.public_key_serial)


    def test_client_init_eddsa(self):
        self._test_client_init_for_algo('EdDSA')

    def test_client_init_rsa(self):
        self._test_client_init_for_algo('RSA')

    def _test_client_methods_for_algo(self, algorithm):
        client = SlipkeyClient(secret_key_input=None, algorithm=algorithm)
        start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        # Test generate_slip
        best_slip, progress_info = client.generate_slip(
            start_time=start_time,
            block_interval=60,
            max_interval=120,
            progress_interval=10, # ms
            target_score=1 # Low target for quick test
        )
        self.assertIsNotNone(best_slip)
        self.assertIn('score', best_slip)
        self.assertIn('nonce', best_slip)
        self.assertIn('hash', best_slip)
        self.assertIn('start_time', best_slip)
        self.assertEqual(best_slip['public_key'], client.public_key_serial)
        self.assertEqual(best_slip['algorithm'], algorithm)
        self.assertTrue(best_slip['score'] > 0) # Should find some score
        self.assertIsNotNone(progress_info)
        self.assertIn('progress', progress_info)
        self.assertIn('current_score', progress_info)

        # Test create_token
        token = client.create_token(best_slip, create=True)
        self.assertIsInstance(token, str)

        # Inspect token (optional, but good for sanity)
        jwt_algo = algorithm
        if algorithm == 'RSA': jwt_algo = 'RS256'

        # To verify with client's public key, we need the public key object
        public_key_obj = client.signing_key.public_key()
        decoded_token = jwt.decode(token, public_key_obj, algorithms=[jwt_algo])
        self.assertEqual(decoded_token['sub'], client.public_key_serial)
        self.assertEqual(decoded_token['slip']['hash'], best_slip['hash'])
        self.assertTrue(decoded_token['create'])


        # Test process_response
        credit, error = client.process_response({'credit': 100, 'message': 'ok'})
        self.assertEqual(credit, 100)
        self.assertEqual(client.credit, 100)
        self.assertIsNone(error)

        credit, error = client.process_response({'error': 'something went wrong'})
        self.assertEqual(client.credit, 100) # Credit should not change on error
        self.assertEqual(error, 'something went wrong')

        credit, error = client.process_response({}) # Empty response
        self.assertEqual(client.credit, 100)
        self.assertIsNotNone(error)


    def test_client_methods_eddsa(self):
        self._test_client_methods_for_algo('EdDSA')

    def test_client_methods_rsa(self):
        self._test_client_methods_for_algo('RSA')


    def _test_server_init_for_algo(self, algorithm):
        # Init without key
        server1 = SlipkeyServer(secret_key_input=None, algorithm=algorithm)
        self.assertIsNotNone(server1.signing_key)
        self.assertIsNotNone(server1.public_key_serial)
        self.assertEqual(server1.algorithm, algorithm)

        # Init with generated key object
        sk = generate_secret_key(algorithm=algorithm)
        server2 = SlipkeyServer(secret_key_input=sk, algorithm=algorithm)
        self.assertEqual(server2.signing_key, sk)

        # Init with serialized key
        serialized_sk = serialize_secret_key(sk, algorithm=algorithm)
        server3 = SlipkeyServer(secret_key_input=serialized_sk, algorithm=algorithm)
        self.assertIsNotNone(server3.signing_key)
        self.assertEqual(server3.public_key_serial, server2.public_key_serial)

    def test_server_init_eddsa(self):
        self._test_server_init_for_algo('EdDSA')

    def test_server_init_rsa(self):
        self._test_server_init_for_algo('RSA')


    def _test_client_server_interaction(self, client_algo, server_algo):
        client = SlipkeyClient(secret_key_input=None, algorithm=client_algo)
        server = SlipkeyServer(secret_key_input=None, algorithm=server_algo)

        # 1. Client generates a genesis slip and token
        start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp() - 5) # 5s in past to be valid

        # Generate a slip with a decent score quickly
        best_slip = {'score':0}
        for _ in range(20): # Try a few times to get a score > 0 for test
            current_slip, _ = client.generate_slip(start_time, 60, 120, 10, 0.5)
            if current_slip.get('score',0) > best_slip.get('score',0):
                best_slip = current_slip
            if best_slip.get('score',0) > 0.5 : break # Found a good enough slip

        self.assertTrue(best_slip['score'] > 0, f"Could not generate a slip with score > 0 for {client_algo}")

        genesis_token = client.create_token(best_slip, create=True)

        # 2. Server validates the genesis slip
        validation_result, error = server.validate_slip(genesis_token)
        self.assertIsNone(error, f"Server validation failed for genesis slip ({client_algo}/{server_algo}): {error}")
        self.assertIsNotNone(validation_result)
        self.assertIn('state', validation_result)
        self.assertIn('creditEarned', validation_result)
        self.assertTrue(validation_result['creditEarned'] > 0)
        self.assertEqual(validation_result['score'], best_slip['score'])

        # 3. Client processes the response
        client.process_response(validation_result) # Update client's credit
        self.assertEqual(client.credit, validation_result['credit'])

        # 4. Client generates a new slip (with the previous state)
        # Ensure new start_time is after or same as the block in the returned state
        # The 'block' in the state is the start_time of the *previous* slip.
        # The new slip's start_time should be current.

        # Simulate some time passing for the next block
        # The 'expires' field in validation_result is block_timestamp + next_len_suggestion
        # So, the next slip's start_time should be around validation_result['block'] + some_work_done_time
        # Or, more simply, current time, ensuring it's after previous block.
        time.sleep(0.01) # Ensure time moves forward a bit
        new_start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp() - 2) # 2s in past

        # Add previous state to the new slip object (client side doesn't do this automatically)
        # The server expects the *original* slip that earned the state, plus the state JWT.
        # This part seems a bit off in the problem description vs. typical flow.
        # A client would typically just submit a *new* PoW. The server uses the 'state' from the *token*
        # to link it to the previous credit.
        # The `slip_data.get('state')` in `validate_slip` implies the *client* includes the prior state JWT
        # inside the *new* slip object it's submitting.

        # Let's assume the client stores the state JWT and includes it in the *next* slip it generates.
        # The current client `generate_slip` does not have a 'state' parameter.
        # The `create_token` method takes a slip object.
        # So, the client must manually add the 'state' JWT to the slip object before tokenization.

        best_slip_stateful = {'score':0}
        for _ in range(20): # Try a few times to get a score > 0 for test
            current_slip_stateful, _ = client.generate_slip(new_start_time, 60, 120, 10, 0.5)
            if current_slip_stateful.get('score',0) > best_slip_stateful.get('score',0):
                best_slip_stateful = current_slip_stateful
            if best_slip_stateful.get('score',0) > 0.5 : break

        self.assertTrue(best_slip_stateful['score'] > 0, f"Could not generate stateful slip with score > 0 for {client_algo}")

        best_slip_stateful['state'] = validation_result['state'] # Add previous state JWT here

        stateful_token = client.create_token(best_slip_stateful, create=False) # create=False now

        # 5. Server validates the new slip
        new_validation_result, new_error = server.validate_slip(stateful_token)
        self.assertIsNone(new_error, f"Server validation failed for stateful slip ({client_algo}/{server_algo}): {new_error}")
        self.assertIsNotNone(new_validation_result)
        self.assertTrue(new_validation_result['creditEarned'] > 0)
        self.assertTrue(new_validation_result['credit'] > validation_result['credit']) # Total credit should increase
        self.assertEqual(new_validation_result['score'], best_slip_stateful['score'])

        # Test Replay Attack
        replay_validation_result, replay_error = server.validate_slip(stateful_token)
        self.assertIsNotNone(replay_error, "Server should have detected replay attack.")
        self.assertIsNone(replay_validation_result)
        self.assertIn("Replayed nonce", replay_error)
        server.seen_nonces.clear() # Clear for next tests if any

    def test_client_server_interaction_eddsa_eddsa(self):
        self._test_client_server_interaction('EdDSA', 'EdDSA')

    def test_client_server_interaction_rsa_rsa(self):
        self._test_client_server_interaction('RSA', 'RSA')

    # It's also possible to test client EdDSA / server RSA if JWTs are compatible (e.g. client signs with EdDSA, server state with RSA)
    # However, the current `validate_slip` expects the client's `slip.algorithm` to match how the server verifies the client token.
    # And `slip.public_key` is used in hashing. So, algos must match for client PoW part.
    # The server's own state token can be a different algo, which is handled.

    def _test_server_validate_slip_failures(self, algorithm):
        client = SlipkeyClient(algorithm=algorithm)
        server = SlipkeyServer(algorithm=algorithm)
        start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        # Generate a valid slip for testing modifications
        slip, _ = client.generate_slip(start_time - 10, 60, 120, 1, 0.1) # Ensure some score
        self.assertTrue(slip.get('score',0) > 0, "Failed to generate initial slip for failure tests")

        # 1. Bad Signature (e.g., token signed by a different key)
        wrong_client = SlipkeyClient(algorithm=algorithm)
        bad_sig_token = wrong_client.create_token(slip, create=True)
        _, err = server.validate_slip(bad_sig_token)
        self.assertIsNotNone(err)
        self.assertIn("signature", err.lower())

        # 2. Block (start_time) too far in the future
        future_slip = slip.copy()
        future_slip['start_time'] = start_time + 1000 # 1000s in future
        future_token = client.create_token(future_slip, create=True)
        _, err = server.validate_slip(future_token)
        self.assertIsNotNone(err)
        self.assertIn("future", err.lower())

        # 3. Score too low (or effectively zero if that's how _calculate_score works)
        # Our _calculate_score always > 0 if hash is non-empty.
        # Let's simulate a hash mismatch leading to effectively zero or different score.
        zero_score_slip = slip.copy()
        original_hash = zero_score_slip['hash']
        zero_score_slip['hash'] = "mismatchedhash" + original_hash # Change hash but not score in slip
        # Server will recalculate hash, it won't match slip['hash'], so this is a hash mismatch test.
        # If we wanted to test score calculation itself, we'd need a nonce that produces a 0 score.
        mismatch_hash_token = client.create_token(zero_score_slip, create=True)
        _, err = server.validate_slip(mismatch_hash_token)
        self.assertIsNotNone(err)
        self.assertIn("hash mismatch", err.lower())
        server.seen_nonces.clear()


        # 4. Incorrect `create` flag usage
        # 4a. create=True, but state is provided
        valid_token_for_state = client.create_token(slip, create=True)
        res, _ = server.validate_slip(valid_token_for_state) # Get a valid state
        self.assertIsNotNone(res, "Failed to get initial state for create=true with state test")

        slip_with_state = slip.copy()
        slip_with_state['state'] = res['state']
        token_create_true_with_state = client.create_token(slip_with_state, create=True)
        _, err = server.validate_slip(token_create_true_with_state)
        self.assertIsNotNone(err)
        self.assertIn("state must be absent", err.lower())
        server.seen_nonces.clear() # Clean nonce from the valid_token_for_state processing

        # 4b. create=False, but state is absent
        token_create_false_no_state = client.create_token(slip, create=False)
        _, err = server.validate_slip(token_create_false_no_state)
        self.assertIsNotNone(err)
        self.assertIn("state must be present", err.lower())
        server.seen_nonces.clear()


        # 5. State mismatch (e.g., state signed by a different server, or for different pubkey)
        # 5a. State for different pubkey
        res, _ = server.validate_slip(client.create_token(slip, create=True)) # Valid genesis
        server.seen_nonces.clear()

        client2 = SlipkeyClient(algorithm=algorithm) # Different public key
        slip_for_client2, _ = client2.generate_slip(start_time - 5, 60,120,1,0.1)
        self.assertTrue(slip_for_client2.get('score',0) > 0)

        slip_for_client2['state'] = res['state'] # Use state from client1 for client2's slip

        token_mismatched_state_sub = client2.create_token(slip_for_client2, create=False)
        _, err = server.validate_slip(token_mismatched_state_sub)
        self.assertIsNotNone(err)
        self.assertIn("public key in state does not match", err.lower())
        server.seen_nonces.clear()

        # 5b. State signed by different server (harder to test without another server instance)
        # For now, this is implicitly covered if the state token is just garbage.
        garbage_state_slip = slip.copy()
        garbage_state_slip['state'] = "this.is.not.a.jwt"
        token_garbage_state = client.create_token(garbage_state_slip, create=False)
        _, err = server.validate_slip(token_garbage_state)
        self.assertIsNotNone(err)
        self.assertIn("invalid state token", err.lower())
        server.seen_nonces.clear()


    def test_server_validate_slip_failures_eddsa(self):
        self._test_server_validate_slip_failures('EdDSA')

    def test_server_validate_slip_failures_rsa(self):
        self._test_server_validate_slip_failures('RSA')


if __name__ == '__main__':
    unittest.main()
