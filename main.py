# Note : pycrypto library can be used to get a prime number
    # from Crypto.Util import number
    # number.getPrime(n)

# used for large prime generation
import random

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

''' Functions used in Prime Generation'''

# returns random number between 2**(n-1)+1 and 2**n-1
def rBitRandom(r):
    return(random.randrange(2**(r-1)+1, 2**r-1))

# Generate a prime candidate divisible by first primes
def getLowLevelPrime(r):
    while True:
        # obtain a random number
        pc = rBitRandom(r)

        # Test divisibility by pre-gen primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else: 
            return pc
        
def isMillerRabinPassed(mrc, trials=20):
    ec = mrc - 1
    s = 0

    while ec % 2 == 0:
        ec //= 2
        s += 1

    for _ in range(trials):
        a = random.randrange(2, mrc - 1)
        x = pow(a, ec, mrc)

        if x == 1 or x == mrc - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, mrc)
            if x == mrc - 1:
                break
        else:
            return False
    return True

# Primes are generated for both keys p and q
def generatePrimes():
    while True:
        bitAmount = 1024
        prime_candidate = getLowLevelPrime(bitAmount)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else: 
            return prime_candidate

''' Mathematical Functions '''

# Power Function
def power(base, expo, m):
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res

# Function to find modular inverse of e modulo phi(n)
# Calculating phi(n) using Extended Euclidean
def modInverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    g, x, y = egcd(e, phi)
    if g != 1:
        return None  # modular inverse does not exist
    else:
        return x % phi

# Function to calculate gcd
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

''' Encryption and Decryption '''

# Encrypt message using public key (e, n)
def encrypt(m, e, n):
    return power(m, e, n)

# Decrypt message using private key (d, n)
def decrypt(c, d, n):
    return power(c, d, n)

''' Key Generation '''

def generateKeys():
    while True:
        p = generatePrimes()
        q = generatePrimes()
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e, where 1 < e < phi(n) and gcd(e, phi(n)) == 1
    e = 65537
    if gcd(e, phi) != 1:
        # fallback if 65537 doesn't work
        for candidate in range(3, phi, 2):
            if gcd(candidate, phi) == 1:
                e = candidate
                break

    # Compute d such athat e * d = 1 (mod phi(n))
    d = modInverse(e, phi)    

    return e, d, n

''' Padding Functions '''

if __name__ == '__main__':
    e, d, n = generateKeys()

    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    # Message
    M = "This is a message"
    print(f"Original Message: {M}")

    m_int = int.from_bytes(M.encode(), 'big')

    # Check message size is within bounds
    if m_int >= n:
        raise ValueError("Message too large for the key size. Use smaller message or larger key.")

    # Encrypt the message
    C = encrypt(m_int, e, n)
    print(f"Encrypted Message: {C}")

    # Decrypt the message
    decrypted_int = decrypt(C, d, n)

    # Convert integer back to string
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
    decrypted_message = decrypted_bytes.decode()

    print(f"Decrypted Message: {decrypted_message}")