import random
import math

# =============================================================================
# 1. Math Helpers (The "Engine")
# =============================================================================

def horner_pow(base, exp, mod):
    """
    Manual implementation of modular exponentiation using Horner's scheme
    (Square and Multiply).
    """
    res = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def modinv(a, m):
    """Calculates modular inverse: a^-1 mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

# =============================================================================
# 2. Prime Generation (Miller-Rabin)
# =============================================================================

def sieve_of_eratosthenes(limit):
    """Generates a list of primes up to 'limit'."""
    is_prime = [True] * (limit + 1)
    p = 2
    while (p * p <= limit):
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
        p += 1
    return [p for p in range(2, limit + 1) if is_prime[p]]

# Pre-compute small primes for trial division (optimization)
# Filtering up to 1000 removes ~90% of composites cheaply.
SMALL_PRIMES = sieve_of_eratosthenes(1000)

def is_probable_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2: return False
    # Trial division for speed
    for p in SMALL_PRIMES:
        if n == p: return True
        if n % p == 0: return False

    # n - 1 = 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n)
        if math.gcd(a, n) != 1:
            return False
        
        x = horner_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(s - 1):
            x = horner_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_random_prime(bits):
    """Generates a prime number of 'bits' length."""
    n0 = 1 << (bits - 1)
    n1 = (1 << bits) - 1
    
    while True:
        x = random.randint(n0, n1)
        # Ensure odd
        if x % 2 == 0: x += 1
        
        # Search sequence x, x+2, x+4...
        for m in range(x, n1 + 1, 2):
            if is_probable_prime(m):
                return m
        # If we reached end of interval, loop restarts with new random x

def generate_two_prime_pairs(bits=256):
    """
    Generates two pairs (p,q) and (p1,q1) such that n <= n1.
    """
    while True:
        p, q = generate_random_prime(bits), generate_random_prime(bits)
        p1, q1 = generate_random_prime(bits), generate_random_prime(bits)
        
        n = p * q
        n1 = p1 * q1
        
        if n <= n1:
            return (p, q), (p1, q1)

# =============================================================================
# 3. High-Level RSA Procedures (The Assignment)
# =============================================================================

def GenerateKeyPair(p, q):
    """
    Generates RSA keys from primes p and q.
    Returns: ((e, n), (d, p, q))
    """
    if p == q: 
        raise ValueError("p and q must be different")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    
    if math.gcd(e, phi) != 1:
        raise ValueError("Invalid 'e' for these primes")
        
    d = modinv(e, phi)
    return (e, n), (d, p, q)

def Encrypt(message, public_key):
    """C = M^e mod n"""
    e, n = public_key
    if not (0 <= message < n): 
        raise ValueError("Message too large")
    return horner_pow(message, e, n)

def Decrypt(ciphertext, private_key):
    """M = C^d mod n"""
    d, p, q = private_key
    return horner_pow(ciphertext, d, p * q)

def Sign(message, private_key):
    """S = M^d mod n (Mathematically same as Decrypt)"""
    d, p, q = private_key
    if not (0 <= message < p * q): 
        raise ValueError("Message too large")
    return horner_pow(message, d, p * q)

def Verify(message, signature, public_key):
    """Checks if M == S^e mod n"""
    e, n = public_key
    return horner_pow(signature, e, n) == message

def SendKey(k, receiver_pub, sender_priv):
    """
    Protocol:
    1. Sign k with My Priv -> S
    2. Encrypt k with Their Pub -> k1
    3. Encrypt S with Their Pub -> S1
    """
    # Protocol constraint check
    n_sender = sender_priv[1] * sender_priv[2]
    n_receiver = receiver_pub[1]
    if n_sender > n_receiver:
        raise ValueError("Protocol Error: Sender modulus > Receiver modulus")

    S = Sign(k, sender_priv)
    k1 = Encrypt(k, receiver_pub)
    S1 = Encrypt(S, receiver_pub)
    return k1, S1

def ReceiveKey(k1, S1, receiver_priv, sender_pub):
    """
    Protocol:
    1. Decrypt k1 -> k
    2. Decrypt S1 -> S
    3. Verify k vs S using Sender Pub
    """
    k = Decrypt(k1, receiver_priv)
    S = Decrypt(S1, receiver_priv)
    
    if Verify(k, S, sender_pub):
        return k
    else:
        raise ValueError("Authentication Failed: Invalid Signature")

# =============================================================================
# 4. Text Utilities (Text <-> Int)
# =============================================================================

def text_to_int(text):
    """Converts a string to an integer."""
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_text(number):
    """Converts an integer back to a string."""
    # We need to calculate number of bytes. 
    # (number.bit_length() + 7) // 8 calculates the ceiling of division by 8
    num_bytes = (number.bit_length() + 7) // 8
    return number.to_bytes(num_bytes, 'big').decode('utf-8')

# =============================================================================
# Self-Check / Demo
# =============================================================================
if __name__ == "__main__":
    print("=== RSA Student Lab Demo ===")
    print("Generating keys (256-bit)...")
    (p, q), _ = generate_two_prime_pairs(256)
    pub, priv = GenerateKeyPair(p, q)
    
    # Example 1: Raw Integer (The Math)
    print("\n[1] Testing Raw Integer:")
    msg_int = 123456789
    cipher_int = Encrypt(msg_int, pub)
    decrypted_int = Decrypt(cipher_int, priv)
    print(f"  Original: {msg_int}")
    print(f"  Decrypted: {decrypted_int}")
    assert msg_int == decrypted_int
    
    # Example 2: Text Message (The App)
    print("\n[2] Testing Text Message:")
    message_str = "Hello, RSA!"
    print(f"  Original Text: '{message_str}'")
    
    # Convert to Int -> Encrypt -> Decrypt -> Convert to Text
    m_int = text_to_int(message_str)
    print(f"  As Integer:    {m_int}")
    
    c_int = Encrypt(m_int, pub)
    print(f"  Encrypted (C): {c_int}")
    
    d_int = Decrypt(c_int, priv)
    result_str = int_to_text(d_int)
    print(f"  Decrypted Txt: '{result_str}'")
    
    assert message_str == result_str
    print("\n✅ Demo Success! System works for Ints and Strings.")
