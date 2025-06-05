import unittest
import time # For simulating time progression
import datetime
from slipkey_sdk.slipkey import (
    SlipkeyClient, SlipkeyServer,
    SlipkeyClientConfig, SlipkeyServerConfig, # Import new Config classes
    ServerCreditMetadata, # Import for custom credit calculator test
    generate_secret_key, serialize_secret_key, generate_public_key, # Keep existing utils
    pem_to_jwk, jwk_to_pem # Import new utils
)
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend # For JWK tests
import jwt # For inspecting tokens
import json # For JWK comparisons / pretty printing

# Helper to get current UTC timestamp as ISO string
def current_iso_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class TestSlipkeyUtils(unittest.TestCase):
    def test_pem_jwk_rsa_conversion(self):
        # Generate RSA key
        private_key_obj = generate_secret_key(algorithm='RSA')
        self.assertIsInstance(private_key_obj, rsa.RSAPrivateKey)

        public_key_obj = private_key_obj.public_key()

        # Serialize public key to PEM
        pem_public_key_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem_public_key_str = pem_public_key_bytes.decode('utf-8')
        self.assertTrue(pem_public_key_str.startswith("-----BEGIN PUBLIC KEY-----"))

        # Convert PEM to JWK
        jwk_output = pem_to_jwk(pem_public_key_str)
        self.assertIsInstance(jwk_output, dict)
        self.assertEqual(jwk_output['kty'], 'RSA')
        self.assertIn('n', jwk_output)
        self.assertIn('e', jwk_output)
        self.assertEqual(jwk_output['alg'], 'RS256') # As per current pem_to_jwk

        # Convert JWK back to PEM
        reconstructed_pem_str = jwk_to_pem(jwk_output)
        self.assertEqual(pem_public_key_str.strip(), reconstructed_pem_str.strip())

    def test_invalid_pem_to_jwk(self):
        with self.assertRaises(ValueError): # Or specific cryptography error
            pem_to_jwk("-----BEGIN FOO BAR-----")

        # Test with non-RSA PEM (e.g., EdDSA public key if it had a standard PEM, which it doesn't for raw pubkey)
        # For now, just an invalid format is enough.

    def test_invalid_jwk_to_pem(self):
        with self.assertRaises(ValueError):
            jwk_to_pem({"kty": "EC"}) # Wrong kty
        with self.assertRaises(ValueError):
            jwk_to_pem({"kty": "RSA", "n": "abc"}) # Missing 'e'
        with self.assertRaises(ValueError):
            jwk_to_pem({"kty": "RSA", "e": "def"}) # Missing 'n'
        with self.assertRaises(Exception): # base64 decode error or int conversion
             jwk_to_pem({"kty": "RSA", "n": "!", "e": "?"})


class TestSlipkeyClient(unittest.TestCase):
    def test_client_init_rsa(self):
        config = SlipkeyClientConfig(algorithm='RSA')
        client = SlipkeyClient(config=config)
        self.assertIsNotNone(client.signing_key)
        self.assertEqual(client.algorithm, 'RSA')
        self.assertIsNotNone(client.get_public_jwk())
        self.assertIsInstance(client.get_public_jwk(), dict)
        self.assertIsNotNone(client.get_public_pem())
        self.assertTrue(client.get_public_pem().startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertEqual(client.default_target_score, config.default_target_score)
        self.assertEqual(client.default_max_pow_iterations, config.default_max_pow_iterations)

    def test_client_init_eddsa(self):
        config = SlipkeyClientConfig(algorithm='EdDSA')
        client = SlipkeyClient(config=config)
        self.assertIsNotNone(client.signing_key)
        self.assertEqual(client.algorithm, 'EdDSA')
        self.assertIsNone(client.get_public_jwk()) # EdDSA JWK not primary focus / different format
        self.assertIsNone(client.get_public_pem()) # EdDSA uses hex serial
        self.assertIsNotNone(client.public_key_serial) # Hex string

    def test_calculate_score(self):
        # Test this internal method (it's identical in client and server)
        client_cfg = SlipkeyClientConfig()
        client = SlipkeyClient(client_cfg) # Dummy client to access method

        score, _ = client._calculate_score("000abc")
        self.assertEqual(score, 0)
        score, _ = client._calculate_score("12345")
        self.assertEqual(score, 0)
        score, _ = client._calculate_score("00000") # Hash value, not the input
        # To test "00000" as hash, we'd need to find input that produces it.
        # Instead, test edge cases based on direct hash values
        test_hash_5_zeros = "00000" + "f" * (64-5)
        score, _ = client._calculate_score(test_hash_5_zeros) # Mocking that data_to_hash produced this
        self.assertEqual(score, 5, "Score should be 5 for 5 leading zeros")

        test_hash_no_zeros = "f" * 64
        score, _ = client._calculate_score(test_hash_no_zeros)
        self.assertEqual(score, 0, "Score should be 0 for no leading zeros")

        test_hash_all_zeros = "0" * 64
        score, _ = client._calculate_score(test_hash_all_zeros)
        self.assertEqual(score, 64, "Score should be 64 for all zeros")

        score, _ = client._calculate_score("") # Empty hash string (unlikely but test)
        self.assertEqual(score, 0)


    def test_generate_slip_rsa(self):
        config = SlipkeyClientConfig(algorithm='RSA', default_target_score=1)
        client = SlipkeyClient(config)
        block_iso = current_iso_utc()

        slip_details = client.generate_slip(block_iso, None, target_score=1, max_iterations=100000)

        self.assertIsInstance(slip_details, dict)
        self.assertGreaterEqual(slip_details['score'], 1)
        self.assertEqual(slip_details['start_time'], block_iso)
        self.assertIsNotNone(slip_details['nonce'])
        self.assertIsNotNone(slip_details['hash'])
        self.assertEqual(slip_details['algorithm'], 'RSA')
        self.assertEqual(slip_details['public_key_for_pow'], client.get_public_pem())
        self.assertIn('iterations_taken', slip_details)
        self.assertLessEqual(slip_details['iterations_taken'], 100000)

    def test_generate_slip_max_iterations_exception(self):
        config = SlipkeyClientConfig(algorithm='RSA', default_target_score=100) # High target
        client = SlipkeyClient(config)
        with self.assertRaisesRegex(Exception, "Proof-of-Work failed"):
            client.generate_slip(current_iso_utc(), None, target_score=100, max_iterations=10)

    def test_generate_signed_slip_rsa(self):
        client_cfg = SlipkeyClientConfig(algorithm='RSA', default_target_score=1)
        client = SlipkeyClient(client_cfg)
        block_iso = current_iso_utc()

        result = client.generate_signed_slip(block_iso, None, create=True)
        self.assertIn('token', result)
        self.assertIn('pow_details', result)
        self.assertIn('slip_payload_for_jwt', result)

        token = result['token']
        # Decode and verify JWT
        public_key_obj = client.signing_key.public_key()
        decoded_token = jwt.decode(token, public_key_obj, algorithms=['RS256'])

        self.assertEqual(decoded_token['block'], block_iso)
        self.assertIsNotNone(decoded_token['nonce'])
        self.assertIsNone(decoded_token['state']) # Genesis
        self.assertTrue(decoded_token['create'])
        self.assertIsInstance(decoded_token['publicKey'], dict) # JWK
        self.assertEqual(decoded_token['publicKey']['kty'], 'RSA')
        self.assertNotIn('sub', decoded_token)
        self.assertNotIn('slip', decoded_token) # No nested slip

    def test_generate_signed_slip_eddsa(self):
        client_cfg = SlipkeyClientConfig(algorithm='EdDSA', default_target_score=1)
        client = SlipkeyClient(client_cfg)
        block_iso = current_iso_utc()

        result = client.generate_signed_slip(block_iso, None, create=True)
        token = result['token']
        public_key_obj = client.signing_key.public_key()
        decoded_token = jwt.decode(token, public_key_obj, algorithms=['EdDSA'])

        self.assertEqual(decoded_token['publicKey'], client.public_key_serial) # Hex for EdDSA
        self.assertNotIn('sub', decoded_token)

    def test_client_process_response(self):
        client_cfg = SlipkeyClientConfig()
        client = SlipkeyClient(client_cfg)
        credit, err = client.process_response({'credit': 100})
        self.assertEqual(credit, 100)
        self.assertIsNone(err)
        credit, err = client.process_response({'error': 'test error'})
        self.assertEqual(credit, 100) # Should not change
        self.assertEqual(err, 'test error')

class TestSlipkeyServer(unittest.TestCase):
    def test_server_init_rsa(self):
        config = SlipkeyServerConfig(algorithm='RSA')
        server = SlipkeyServer(config)
        self.assertIsNotNone(server.signing_key)
        self.assertEqual(server.algorithm, 'RSA')
        self.assertIsNotNone(server.get_public_jwk())
        self.assertIsNotNone(server.get_public_pem())
        self.assertEqual(server.default_expected_target_score, config.default_expected_target_score)

    def test_server_init_eddsa(self):
        config = SlipkeyServerConfig(algorithm='EdDSA')
        server = SlipkeyServer(config)
        self.assertIsNotNone(server.signing_key)
        self.assertEqual(server.algorithm, 'EdDSA')
        self.assertIsNone(server.get_public_jwk())
        self.assertIsNone(server.get_public_pem())

    # More tests for process_client_token will be in TestIntegration
    # But some unit tests for specific logic can be here.

    def test_default_credit_calculator(self):
        server_cfg = SlipkeyServerConfig(default_expected_target_score=2)
        server = SlipkeyServer(server_cfg) # Uses default calculator

        # Scenario 1: Score meets target
        metadata_good = ServerCreditMetadata(
            block_timestamp="iso", time_solved=datetime.datetime.now(datetime.timezone.utc),
            pow_score=2, chain_length=1, client_public_key_claim_value={},
            previous_credit=0, previous_chain_length=0, is_below_target_score=False
        )
        credit = server._default_calculate_credit(metadata_good)
        self.assertEqual(credit, 0 + (2 * 10) + 1) # 21

        # Scenario 2: Score below target but valid PoW
        metadata_below = ServerCreditMetadata(
            block_timestamp="iso", time_solved=datetime.datetime.now(datetime.timezone.utc),
            pow_score=1, chain_length=1, client_public_key_claim_value={},
            previous_credit=0, previous_chain_length=0, is_below_target_score=True
        )
        credit = server._default_calculate_credit(metadata_below)
        self.assertEqual(credit, 0) # No credit change

    def test_custom_credit_calculator(self):
        def my_calc(metadata: ServerCreditMetadata):
            return metadata.previous_credit + metadata.pow_score * 50

        server_cfg = SlipkeyServerConfig(custom_credit_calculator=my_calc)
        server = SlipkeyServer(server_cfg)
        metadata = ServerCreditMetadata(
            block_timestamp="iso", time_solved=datetime.datetime.now(datetime.timezone.utc),
            pow_score=2, chain_length=1, client_public_key_claim_value={},
            previous_credit=10, previous_chain_length=0, is_below_target_score=False
        )
        credit = server.credit_calculator(metadata)
        self.assertEqual(credit, 10 + 2 * 50) # 110


class TestIntegration(unittest.TestCase):

    def _run_client_server_loop(self, client_alg, server_alg, client_target_score, server_expected_score):
        client_sk_obj = generate_secret_key(client_alg)
        server_sk_obj = generate_secret_key(server_alg) # Can be same or different for test

        client_cfg = SlipkeyClientConfig(
            secret_key_input=client_sk_obj,
            algorithm=client_alg,
            default_target_score=client_target_score
        )
        client = SlipkeyClient(client_cfg)

        server_cfg = SlipkeyServerConfig(
            secret_key_input=server_sk_obj,
            algorithm=server_alg,
            default_expected_target_score=server_expected_score
        )
        server = SlipkeyServer(server_cfg)

        # 1. Genesis Slip
        block1_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
        signed_slip1 = client.generate_signed_slip(block1_iso, None, create=True)

        resp1, err1 = server.process_client_token(signed_slip1['token'])
        self.assertIsNone(err1, f"Server error on genesis slip: {err1}")
        self.assertIsNotNone(resp1)

        is_below1 = resp1['score'] < server_expected_score
        self.assertEqual(resp1['is_below_target_score'], is_below1)

        expected_credit1 = 0
        if not is_below1:
            expected_credit1 = (resp1['score'] * 10) + resp1['len'] # Default calc: prev_credit=0
        self.assertEqual(resp1['credit'], expected_credit1)
        self.assertEqual(resp1['creditEarned'], expected_credit1)
        self.assertEqual(resp1['len'], 1)

        client_credit1, _ = client.process_response(resp1)
        self.assertEqual(client_credit1, expected_credit1)
        current_server_state_for_client = resp1['state']

        # 2. Subsequent Slip
        block2_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).isoformat()
        signed_slip2 = client.generate_signed_slip(block2_iso, current_server_state_for_client, create=False, target_score=client_target_score + 1) # Try higher score

        resp2, err2 = server.process_client_token(signed_slip2['token'])
        self.assertIsNone(err2, f"Server error on subsequent slip: {err2}")
        self.assertIsNotNone(resp2)

        is_below2 = resp2['score'] < server_expected_score
        self.assertEqual(resp2['is_below_target_score'], is_below2)

        expected_credit2 = expected_credit1
        if not is_below2:
            expected_credit2 += (resp2['score'] * 10) + resp2['len']

        self.assertEqual(resp2['credit'], expected_credit2)
        self.assertEqual(resp2['creditEarned'], expected_credit2 - expected_credit1)
        self.assertEqual(resp2['len'], 2) # Chain length increases

        # Test replay of the first token
        _, err_replay = server.process_client_token(signed_slip1['token'])
        self.assertIsNotNone(err_replay)
        self.assertIn("Replayed nonce", err_replay)

    def test_rsa_loop_scores_met(self):
        self._run_client_server_loop('RSA', 'RSA', client_target_score=1, server_expected_score=1)

    def test_eddsa_loop_scores_met(self):
        self._run_client_server_loop('EdDSA', 'EdDSA', client_target_score=1, server_expected_score=1)

    def test_rsa_loop_client_below_server_target(self):
        # Client aims for 1, server expects 2. Client should get no credit initially.
        self._run_client_server_loop('RSA', 'RSA', client_target_score=1, server_expected_score=2)

    def test_process_client_token_failures(self):
        client_cfg_rsa = SlipkeyClientConfig(algorithm='RSA')
        client_rsa = SlipkeyClient(client_cfg_rsa)

        server_cfg_rsa = SlipkeyServerConfig(algorithm='RSA', default_expected_target_score=1)
        server_rsa = SlipkeyServer(server_cfg_rsa)

        block_iso = current_iso_utc()

        # Valid token for manipulation
        valid_signed_slip = client_rsa.generate_signed_slip(block_iso, None, True, target_score=1)

        # a) Invalid client signature (e.g. token tampered, or signed by wrong key)
        # Create another client with a different key
        other_client_sk = generate_secret_key('RSA')
        other_client_cfg = SlipkeyClientConfig(secret_key_input=other_client_sk, algorithm='RSA')
        other_client = SlipkeyClient(other_client_cfg)

        # Generate slip details with original client, but sign with other_client's key by re-creating token
        # This is a bit artificial; easier to just tamper with the JWT string if we knew its structure.
        # For now, let's simulate by creating a token with "correct" payload but wrong key.
        payload_for_wrong_sig = valid_signed_slip['slip_payload_for_jwt']
        # We need to use the internal _create_token structure of other_client
        # This is hard to test without exposing more internals or actually tampering the string.
        # A simpler "wrong signature" test is if the server expects RSA and client sends EdDSA signed token.
        # For now, let's use a token from an EdDSA client.
        client_cfg_eddsa = SlipkeyClientConfig(algorithm='EdDSA')
        client_eddsa = SlipkeyClient(client_cfg_eddsa)
        eddsa_signed_slip = client_eddsa.generate_signed_slip(block_iso, None, True, target_score=1)

        if server_rsa.algorithm == 'RSA': # Ensure server is RSA for this test part
            _, err = server_rsa.process_client_token(eddsa_signed_slip['token'])
            self.assertIsNotNone(err, "Server should fail EdDSA token if expecting RSA based on _verify_and_decode_client_token logic")
            self.assertIn("algorithm", err.lower(), "Error should be about algorithm/key type mismatch for signature")
            # This test depends on how _verify_and_decode handles alg mismatch vs. signature error.
            # PyJWT might raise InvalidAlgorithmError or InvalidSignatureError.

        # b) Malformed token (e.g. not a JWT)
        _, err = server_rsa.process_client_token("not.a.jwt.string")
        self.assertIsNotNone(err)
        self.assertIn("invalid", err.lower()) # PyJWT decode error

        # c) Missing critical claims
        # Create a token manually with missing claims
        claims_no_pk = {
            "block": block_iso, "nonce": "testnonce", "create": True,
            "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
            "exp": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60)).timestamp()
        }
        token_no_pk = jwt.encode(claims_no_pk, client_rsa.signing_key, algorithm="RS256")
        _, err = server_rsa.process_client_token(token_no_pk)
        self.assertIsNotNone(err)
        self.assertIn("Missing 'publicKey' claim", err)

        # d) PoW score is zero (or doesn't meet server's absolute minimum like >0)
        # Need to craft a slip that results in score 0 from server's _calculate_score
        # This is hard to do reliably without knowing specific hash inputs.
        # Instead, we can mock _calculate_score on the server or test via expected_target_score.
        # The test _run_client_server_loop already covers is_below_target_score.
        # The server's process_client_token has `if not (recalculated_score > 0):`
        # To test this, one would need to find a nonce that produces score 0.
        # For now, this specific "score is exactly 0" case is hard to force.

        # e) State progression errors
        # e.1. create=True, but state is provided
        resp_genesis, _ = server_rsa.process_client_token(valid_signed_slip['token']) # Get a valid state
        server_rsa.seen_nonces.clear() # Clear nonce from previous

        signed_slip_create_with_state = client_rsa.generate_signed_slip(
            (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)).isoformat(),
            resp_genesis['state'], # Providing state
            create=True # But create is True
        )
        _, err = server_rsa.process_client_token(signed_slip_create_with_state['token'])
        self.assertIsNotNone(err)
        self.assertIn("State must be absent when 'create' flag is True", err)
        server_rsa.seen_nonces.clear()

        # e.2. create=False, but state is None
        signed_slip_nocreate_no_state = client_rsa.generate_signed_slip(
            (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=10)).isoformat(),
            None, # No state
            create=False # But create is False
        )
        _, err = server_rsa.process_client_token(signed_slip_nocreate_no_state['token'])
        self.assertIsNotNone(err)
        self.assertIn("State must be present when 'create' flag is False", err)
        server_rsa.seen_nonces.clear()

        # f) Invalid previous state JWT
        signed_slip_bad_prev_state = client_rsa.generate_signed_slip(
            (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=15)).isoformat(),
            "not.a.valid.state.jwt",
            create=False
        )
        _, err = server_rsa.process_client_token(signed_slip_bad_prev_state['token'])
        self.assertIsNotNone(err)
        self.assertIn("Invalid state token", err)

# Old test structure (to be removed or refactored)
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

    # Client init tests are now part of TestSlipkeyClient
    # Client methods tests are now part of TestSlipkeyClient and TestIntegration
    # Server init tests are now part of TestSlipkeyServer
    # Client-server interaction tests are now part of TestIntegration
    # Server failure tests are now part of TestIntegration or more specific server unit tests.


if __name__ == '__main__':
    unittest.main()
