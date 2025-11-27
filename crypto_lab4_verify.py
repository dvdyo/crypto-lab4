# crypto_lab4_verify.py
import requests
from my_rsa import GenerateKeyPair, generate_two_prime_pairs, Encrypt, Decrypt, Sign, Verify, SendKey, ReceiveKey, text_to_int

BASE_URL = "http://asymcryptwebservice.appspot.com/rsa"
session = requests.Session()

def hex_to_int(hex_str):
    return int(hex_str, 16)

def int_to_hex(number):
    return hex(number)[2:].upper()

def get_server_key(key_size=256):
    """Retrieves the server's public key."""
    url = f"{BASE_URL}/serverKey?keySize={key_size}"
    resp = session.get(url)
    data = resp.json()
    n = hex_to_int(data['modulus'])
    e = hex_to_int(data['publicExponent'])
    return (e, n)

def test_text_messaging(my_text_message, server_pub_key):
    """
    Test 7: Text Message Encryption
    We encrypt text -> Server decrypts and returns the text.
    """
    print("\n--- [Test 7] TEXT Message: Local Encrypt -> Server Decrypt ---")

    # 1. Convert Text -> Int using our new helper
    msg_int = text_to_int(my_text_message)

    # 2. Encrypt
    ciphertext_int = Encrypt(msg_int, server_pub_key)
    ciphertext_hex = int_to_hex(ciphertext_int)

    # 3. Send to server with expectedType=TEXT
    url = f"{BASE_URL}/decrypt?cipherText={ciphertext_hex}&expectedType=TEXT"
    resp = session.get(url)
    data = resp.json()

    if 'message' not in data:
        print("Error response:", data)
        return False

    decrypted_text_from_server = data['message']

    print(f"Original: '{my_text_message}'")
    print(f"Server returned: '{decrypted_text_from_server}'")

    if my_text_message == decrypted_text_from_server:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_encryption(my_message_int, server_pub_key):
    """
    Test 1: Local Encryption -> Server Decryption
    """
    print("\n--- [Test 1] Encryption (Local) -> Decryption (Server) ---")
    # 1. Encrypt locally
    ciphertext_int = Encrypt(my_message_int, server_pub_key)
    ciphertext_hex = int_to_hex(ciphertext_int)

    # 2. Send to server for decryption
    # Server expects 'message' as ciphertext for endpoint /decrypt
    # and expectedType=BYTES (by default, returns hex)
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

    if my_message_int == decrypted_int:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_decryption(my_message_int, my_pub_key, my_priv_key):
    """
    Test 2: Server Encryption -> Local Decryption
    """
    print("\n--- [Test 2] Encryption (Server) -> Decryption (Local) ---")
    e, n = my_pub_key
    msg_hex = int_to_hex(my_message_int)

    # 1. Ask server to encrypt for us
    url = f"{BASE_URL}/encrypt?modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}&message={msg_hex}&type=BYTES"
    resp = session.get(url)
    data = resp.json()

    ciphertext_hex = data['cipherText']
    ciphertext_int = hex_to_int(ciphertext_hex)

    # 2. Decrypt locally
    decrypted_int = Decrypt(ciphertext_int, my_priv_key)

    print(f"Original (Int): {my_message_int}")
    print(f"Decrypted(Int): {decrypted_int}")

    if my_message_int == decrypted_int:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_signature_verify(my_message_int, server_pub_key):
    """
    Test 3: Server Sign -> Local Verify
    """
    print("\n--- [Test 3] Sign (Server) -> Verify (Local) ---")
    msg_hex = int_to_hex(my_message_int)

    # 1. Server signs
    url = f"{BASE_URL}/sign?message={msg_hex}&type=BYTES"
    resp = session.get(url)
    data = resp.json()

    if 'signature' not in data:
        print("Error in response:", data)
        return False

    signature_hex = data['signature']
    signature_int = hex_to_int(signature_hex)

    # 2. We verify
    is_valid = Verify(my_message_int, signature_int, server_pub_key)

    print(f"Signature: {signature_hex[:30]}...")
    print(f"Verified:  {is_valid}")

    if is_valid:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_sign_myself(my_message_int, my_pub_key, my_priv_key):
    """
    Test 4: Local Sign -> Server Verify
    """
    print("\n--- [Test 4] Sign (Local) -> Verify (Server) ---")
    e, n = my_pub_key

    # 1. We sign
    signature_int = Sign(my_message_int, my_priv_key)
    signature_hex = int_to_hex(signature_int)
    msg_hex = int_to_hex(my_message_int)

    # 2. Server verifies
    url = f"{BASE_URL}/verify?message={msg_hex}&type=BYTES&signature={signature_hex}&modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}"
    resp = session.get(url)
    data = resp.json()

    server_says_valid = data['verified']
    print(f"Server says verified: {server_says_valid}")

    if server_says_valid:
        print("✅ SUCCESS")
        return True
    else:
        print("❌ FAILED")
        return False

def test_protocol_send(my_priv_key, server_pub_key):
    """
    Test 5: Protocol SendKey (Local -> Server)
    We send a key, server receives it.
    """
    print("\n--- [Test 5] Protocol: SendKey (Local) -> ReceiveKey (Server) ---")

    # Generate random session key k (smaller than n)
    # n (server) ~ 256-512 bit, key 64 bit is fine
    k = 123456789012345

    # Execute SendKey locally
    # Returns (k1, S1)
    k1_int, S1_int = SendKey(k, server_pub_key, my_priv_key)

    k1_hex = int_to_hex(k1_int)
    S1_hex = int_to_hex(S1_int)

    # Send to server
    # Parameters: key (k1), signature (S1), modulus (sender), publicExponent (sender)
    (_, n_sender) = (0, my_priv_key[1]*my_priv_key[2]) # sender modulus

    # Use standard public exponent
    e_sender = 65537

    url = f"{BASE_URL}/receiveKey?key={k1_hex}&signature={S1_hex}&modulus={int_to_hex(n_sender)}&publicExponent={int_to_hex(e_sender)}"

    resp = session.get(url)
    data = resp.json()

    if 'verified' in data and data['verified'] is True:
        received_key_hex = data['key']
        received_key_int = hex_to_int(received_key_hex)
        print(f"Sent Key:     {k}")
        print(f"Server Recvd: {received_key_int}")

        if k == received_key_int:
            print("✅ SUCCESS")
            return True

    print("❌ FAILED")
    print(data)
    return False

def test_protocol_receive(my_pub_key, my_priv_key):
    """
    Test 6: Protocol ReceiveKey (Server -> Local)
    Server generates a key and sends it to us.
    """
    print("\n--- [Test 6] Protocol: SendKey (Server) -> ReceiveKey (Local) ---")
    e, n = my_pub_key

    # 1. Ask server to send us a key
    url = f"{BASE_URL}/sendKey?modulus={int_to_hex(n)}&publicExponent={int_to_hex(e)}"
    resp = session.get(url)
    data = resp.json()

    k1_hex = data['key'] # Encrypted key
    S1_hex = data['signature'] # Encrypted signature

    k1_int = hex_to_int(k1_hex)
    S1_int = hex_to_int(S1_hex)

    return k1_int, S1_int


# -------------------------
# MAIN Execution
# -------------------------
if __name__ == "__main__":
    print("=== RSA API Verification Tool ===")
    
    # 1. Get Server Key
    try:
        server_pub_key = get_server_key(key_size=512) # (e, n)
        print(f"Server Key obtained. Modulus length: {server_pub_key[1].bit_length()} bits")
    except Exception as e:
        print(f"Failed to reach server: {e}")
        exit(1)
        
    # 2. Generate Our Keys
    # Important: Our modulus (n) should be <= Server modulus (n1) for the SendKey protocol.
    # Since the server provides a 512-bit key, we will generate approximately the same size.
    print("Generating local keys (approx 512 bit modulus)...")
    (p, q), _ = generate_two_prime_pairs(bits=256) # 256*2 = 512 bit modulus
    
    my_pub_key, my_priv_key = GenerateKeyPair(p, q)
    print(f"Local Key generated. Modulus length: {my_pub_key[1].bit_length()} bits")
    
    # Check n <= n1 condition
    if my_pub_key[1] > server_pub_key[1]:
        print("⚠️ WARNING: Local modulus is larger than Server modulus.")
        print("Protocol SendKey (Local -> Server) might fail if strictly enforced.")
        
    # Test message
    msg = 123456789
    
    # Run Tests
    test_encryption(msg, server_pub_key)
    test_decryption(msg, my_pub_key, my_priv_key)
    test_signature_verify(msg, server_pub_key)
    test_sign_myself(msg, my_pub_key, my_priv_key)
    test_protocol_send(my_priv_key, server_pub_key)
    
    # Test 6 Special Handling
    try:
        k1, S1 = test_protocol_receive(my_pub_key, my_priv_key)
        # ReceiveKey(k1, S1, receiver_private_key, sender_public_key)
        # We are receiver. Server is sender.
        k_received = ReceiveKey(k1, S1, my_priv_key, server_pub_key)
        print(f"Server sent key: {k_received}")
        print("✅ SUCCESS")
    except Exception as e:
        print(f"❌ FAILED (Receive): {e}")

    # Test 7 Text Message
    test_text_messaging("Hello, KPI!", server_pub_key)