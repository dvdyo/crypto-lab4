import random
import math

# =============================================================================
# 1. math helpers 
# =============================================================================

def horner_pow(base, exp, mod):
    """
    manual implementation of modular exponentiation using horner's scheme
    (square and multiply).
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
    """extended euclidean algorithm."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def modinv(a, m):
    """calculates modular inverse: a^-1 mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

# =============================================================================
# 2. prime generation (miller-rabin)
# =============================================================================

def sieve_of_eratosthenes(limit):
    """generates a list of primes up to 'limit'."""
    is_prime = [True] * (limit + 1)
    p = 2
    while (p * p <= limit):
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
        p += 1
    return [p for p in range(2, limit + 1) if is_prime[p]]

# pre-compute small primes for trial division
SMALL_PRIMES = sieve_of_eratosthenes(1000)

def is_probable_prime(n, k=20):
    """miller-rabin primality test."""
    if n < 2: 
        return False
    # trial division for speed
    for p in SMALL_PRIMES:
        if n == p: 
            return True
        if n % p == 0: 
            return False

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
    """generates a prime number of 'bits' length."""
    n0 = 1 << (bits - 1)
    n1 = (1 << bits) - 1
    
    while True:
        x = random.randint(n0, n1)
        # ensure odd
        if x % 2 == 0: 
            x += 1
        
        # search sequence x, x+2, x+4...
        for m in range(x, n1 + 1, 2):
            if is_probable_prime(m):
                return m
        # if we reached end of interval, loop restarts with new random x

def generate_two_prime_pairs(bits=256):
    """
    generates two pairs (p,q) and (p1,q1) such that n <= n1.
    """
    while True:
        p, q = generate_random_prime(bits), generate_random_prime(bits)
        p1, q1 = generate_random_prime(bits), generate_random_prime(bits)
        
        n = p * q
        n1 = p1 * q1
        
        if n <= n1:
            return (p, q), (p1, q1)

# =============================================================================
# 3. high-level rsa procedures 
# =============================================================================

def GenerateKeyPair(p, q):
    """
    generates rsa keys from primes p and q.
    returns: ((e, n), (d, p, q))
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
    """c = m^e mod n"""
    e, n = public_key
    if not (0 <= message < n): 
        raise ValueError("Message too large")
    return horner_pow(message, e, n)

def Decrypt(ciphertext, private_key):
    """m = c^d mod n"""
    d, p, q = private_key
    return horner_pow(ciphertext, d, p * q)

def Sign(message, private_key):
    """s = m^d mod n (mathematically same as decrypt)"""
    d, p, q = private_key
    if not (0 <= message < p * q): 
        raise ValueError("Message too large")
    return horner_pow(message, d, p * q)

def Verify(message, signature, public_key):
    """checks if m == s^e mod n"""
    e, n = public_key
    return horner_pow(signature, e, n) == message

def SendKey(k, receiver_pub, sender_priv):
    """
    protocol:
    1. sign k with my priv -> s
    2. encrypt k with their pub -> k1
    3. encrypt s with their pub -> s1
    """
    # protocol constraint check
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
    protocol:
    1. decrypt k1 -> k
    2. decrypt s1 -> s
    3. verify k vs s using sender pub
    """
    k = Decrypt(k1, receiver_priv)
    S = Decrypt(S1, receiver_priv)
    
    if Verify(k, S, sender_pub):
        return k
    else:
        raise ValueError("Authentication Failed: Invalid Signature")
