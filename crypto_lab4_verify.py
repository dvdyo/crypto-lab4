import requests
from my_rsa import GenerateKeyPair, generate_two_prime_pairs, Encrypt, Decrypt, Sign, Verify, SendKey, ReceiveKey, text_to_int

BASE_URL = "http://asymcryptwebservice.appspot.com/rsa"
session = requests.Session()

# Log files
PRIME_LOG_FILE = "prime_candidates.log"
PROTOCOL_LOG_FILE = "protocol_details.log"

def log_protocol(header, data_dict):
    """Logs protocol values to a separate file to keep terminal clean."""
    try:
        with open(PROTOCOL_LOG_FILE, "a") as f:
            f.write(f"\n=== {header} ===\n")
            for key, value in data_dict.items():
                f.write(f"{key}:\n    {value}\n")
            f.write("="*40 + "\n")
    except Exception:
        pass

def hex_to_int(hex_str):
    return int(hex_str, 16)

def int_to_hex(number):
    return hex(number)[2:].upper()

def get_server_key(key_size=512):
    """retrieves the server's public key."""
    url = f"{BASE_URL}/serverKey?keySize={key_size}"
    resp = session.get(url)
    data = resp.json()
    n = hex_to_int(data['modulus'])
    e = hex_to_int(data['publicExponent'])
    
    log_protocol("Server Key Obtained", {
        "Modulus (n)": int_to_hex(n),
        "Public Exponent (e)": int_to_hex(e)
    })
    return (e, n)



def test_encryption(my_message_int, server_pub_key):
    """
    test 1: local encryption -> server decryption
    """
    print("\n--- [Test 1] Encryption (Local) -> Decryption (Server) ---")
    # 1. encrypt locally
    ciphertext_int = Encrypt(my_message_int, server_pub_key)
    ciphertext_hex = int_to_hex(ciphertext_int)

    # 2. send to server for decryption
    # server expects 'message' as ciphertext for endpoint /decrypt
    # and expectedtype=bytes (by default, returns hex)
    url = f"{BASE_URL}/decrypt?cipherText={ciphertext_hex}&expectedType=BYTES"
    resp = session.get(url)

    if resp.status_code != 200:
        print("Error from server:", resp.text)
        return False

    data = resp.json()
    if 'message' not in data:
         print("Error in response:", data)
         return False

    decrypted_hex = data['message']
    decrypted_int = hex_to_int(decrypted_hex)

    print(f"Original (Int): {my_message_int}")
    print(f"Decrypted(Int): {decrypted_int}")
    
    log_protocol("Test 1: Encryption (Local -> Server)", {
        "Original": my_message_int,
        "Ciphertext (Hex)": ciphertext_hex,
        "Decrypted (Hex)": decrypted_hex,
        "Decrypted (Int)": decrypted_int
    })

    if my_message_int == decrypted_int:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_decryption(my_message_int, my_pub_key, my_priv_key):
    """
    test 2: server encryption -> local decryption
    """
    print("\n--- [Test 2] Encryption (Server) -> Decryption (Local) ---")
    e, n = my_pub_key
    msg_hex = int_to_hex(my_message_int)

    # 1. ask server to encrypt for us
    url = f"{BASE_URL}/encrypt?modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}&message={msg_hex}&type=BYTES"
    resp = session.get(url)
    data = resp.json()

    ciphertext_hex = data['cipherText']
    ciphertext_int = hex_to_int(ciphertext_hex)

    # 2. decrypt locally
    decrypted_int = Decrypt(ciphertext_int, my_priv_key)

    print(f"Original (Int): {my_message_int}")
    print(f"Decrypted(Int): {decrypted_int}")
    
    log_protocol("Test 2: Decryption (Server -> Local)", {
        "Original": my_message_int,
        "Ciphertext (Hex)": ciphertext_hex,
        "Decrypted (Int)": decrypted_int
    })

    if my_message_int == decrypted_int:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_signature_verify(my_message_int, server_pub_key):
    """
    test 3: server sign -> local verify
    """
    print("\n--- [Test 3] Sign (Server) -> Verify (Local) ---")
    msg_hex = int_to_hex(my_message_int)

    # 1. server signs
    url = f"{BASE_URL}/sign?message={msg_hex}&type=BYTES"
    resp = session.get(url)
    data = resp.json()

    if 'signature' not in data:
        print("Error in response:", data)
        return False

    signature_hex = data['signature']
    signature_int = hex_to_int(signature_hex)

    # 2. we verify
    is_valid = Verify(my_message_int, signature_int, server_pub_key)

    print(f"Signature: {signature_hex[:30]}...")
    print(f"Verified:  {is_valid}")
    
    log_protocol("Test 3: Signature (Server -> Local)", {
        "Message": my_message_int,
        "Signature (Hex)": signature_hex,
        "Valid?": is_valid
    })

    if is_valid:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_sign_myself(my_message_int, my_pub_key, my_priv_key):
    """
    test 4: local sign -> server verify
    """
    print("\n--- [Test 4] Sign (Local) -> Verify (Server) ---")
    e, n = my_pub_key

    # 1. we sign
    signature_int = Sign(my_message_int, my_priv_key)
    signature_hex = int_to_hex(signature_int)
    msg_hex = int_to_hex(my_message_int)

    # 2. server verifies
    url = f"{BASE_URL}/verify?message={msg_hex}&type=BYTES&signature={signature_hex}&modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}"
    resp = session.get(url)
    data = resp.json()

    server_says_valid = data['verified']
    print(f"Server says verified: {server_says_valid}")
    
    log_protocol("Test 4: Signature (Local -> Server)", {
        "Message": my_message_int,
        "Signature (Hex)": signature_hex,
        "Server Verified?": server_says_valid
    })

    if server_says_valid:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_protocol_send(my_priv_key, server_pub_key):
    """
    test 5: protocol sendkey (local -> server)
    we send a key, server receives it.
    """
    print("\n--- [Test 5] Protocol: SendKey (Local) -> ReceiveKey (Server) ---")

    # generate random session key k (smaller than n)
    # n (server) ~ 256-512 bit, key 64 bit is fine
    k = 123456789012345

    # execute sendkey locally
    # returns (k1, s1)
    k1_int, S1_int = SendKey(k, server_pub_key, my_priv_key)

    k1_hex = int_to_hex(k1_int)
    S1_hex = int_to_hex(S1_int)

    # send to server
    # parameters: key (k1), signature (s1), modulus (sender), publicexponent (sender)
    (_, n_sender) = (0, my_priv_key[1]*my_priv_key[2]) # sender modulus

    # use standard public exponent
    e_sender = 65537

    url = f"{BASE_URL}/receiveKey?key={k1_hex}&signature={S1_hex}&modulus={int_to_hex(n_sender)}&publicExponent={int_to_hex(e_sender)}"

    resp = session.get(url)
    data = resp.json()

    if 'verified' in data and data['verified'] is True:
        received_key_hex = data['key']
        received_key_int = hex_to_int(received_key_hex)
        print(f"Sent Key:     {k}")
        print(f"Server Recvd: {received_key_int}")
        
        log_protocol("Test 5: SendKey (Local -> Server)", {
            "Session Key (k)": k,
            "Encrypted Key (k1)": k1_hex,
            "Encrypted Signature (S1)": S1_hex,
            "Server Received": received_key_int
        })

        if k == received_key_int:
            print("✅ SUCCESS")
            return True

    print("❌ FAILED")
    print(data)
    return False

def test_protocol_receive(my_pub_key, my_priv_key):
    """
    test 6: protocol receivekey (server -> local)
    server generates a key and sends it to us.
    """
    print("\n--- [Test 6] Protocol: SendKey (Server) -> ReceiveKey (Local) ---")
    e, n = my_pub_key

    # 1. ask server to send us a key
    url = f"{BASE_URL}/sendKey?modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}"
    resp = session.get(url)
    data = resp.json()

    k1_hex = data['key'] # encrypted key
    S1_hex = data['signature'] # encrypted signature

    k1_int = hex_to_int(k1_hex)
    S1_int = hex_to_int(S1_hex)
    
    log_protocol("Test 6: ReceiveKey (Server -> Local)", {
        "Encrypted Key (k1)": k1_hex,
        "Encrypted Signature (S1)": S1_hex
    })

    return k1_int, S1_int


# -------------------------
# main execution
# -------------------------
if __name__ == "__main__":
    # reset the log files for a fresh run
    with open(PRIME_LOG_FILE, "w") as f:
        f.write("=== RSA Prime Generation Log ===\n")
        f.write("This file contains candidates checked during prime generation.\n\n")
        
    with open(PROTOCOL_LOG_FILE, "w") as f:
        f.write("=== RSA Protocol Execution Log ===\n")
        f.write("This file contains the full keys, signatures, and ciphertexts.\n\n")

    print("=== RSA API Verification Tool ===")
    
    # 1. get server key
    try:
        server_pub_key = get_server_key(key_size=512) # (e, n)
        print(f"Server Key obtained. Modulus length: {server_pub_key[1].bit_length()} bits")
    except Exception as e:
        print(f"Failed to reach server: {e}")
        exit(1)
        
    # 2. generate our keys
    # important: our modulus (n) should be <= server modulus (n1) for the sendkey protocol.
    # since the server provides a 512-bit key, we will generate approximately the same size.
    print("Generating local keys (approx 512 bit modulus)...")
    (p, q), _ = generate_two_prime_pairs(bits=256) # 256*2 = 512 bit modulus
    
    my_pub_key, my_priv_key = GenerateKeyPair(p, q)
    print(f"Local Key generated. Modulus length: {my_pub_key[1].bit_length()} bits")
    
    log_protocol("Local Key Generation", {
        "Modulus (n)": int_to_hex(my_pub_key[1]),
        "Public Exponent (e)": int_to_hex(my_pub_key[0]),
        "Private Exponent (d)": int_to_hex(my_priv_key[0])
    })
    
    # check n <= n1 condition
    if my_pub_key[1] > server_pub_key[1]:
        print("⚠️ WARNING: Local modulus is larger than Server modulus.")
        print("Protocol SendKey (Local -> Server) might fail if strictly enforced.")
        
    # test message
    msg = 123456789
    
    # run tests
    test_encryption(msg, server_pub_key)
    test_decryption(msg, my_pub_key, my_priv_key)
    test_signature_verify(msg, server_pub_key)
    test_sign_myself(msg, my_pub_key, my_priv_key)
    test_protocol_send(my_priv_key, server_pub_key)
    
    # test 6 special handling
    try:
        k1, S1 = test_protocol_receive(my_pub_key, my_priv_key)
        # receivekey(k1, s1, receiver_private_key, sender_public_key)
        # we are receiver. server is sender.
        k_received = ReceiveKey(k1, S1, my_priv_key, server_pub_key)
        print(f"Server sent key: {k_received}")
        
        log_protocol("Test 6 Result", {
            "Decrypted Key": k_received
        })
        
        print("✅ SUCCESS")
    except Exception as e:
        print(f"❌ FAILED (Receive): {e}")


