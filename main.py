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

def rBitRandom(r):
    # returns random number 
    # between 2**(n-1)+1 and 2**n-1
    return(random.randrange(2**(r-1)+1, 2**r-1))

def getLowLevelPrime(r):
    # Generate a prime candidate
    # divisible by first primes
    while True:
        # obtain a random number
        pc = rBitRandom(r)

        # Test divisibility by pre-gen primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else: 
            return pc
        
def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1

    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
    
    # set number of trials here
    numberOfRabinTrials = 20

    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
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