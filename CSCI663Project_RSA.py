######## INFORMATION ############################################################
#                                                                               #
# CSCI663G VA                                                                   #
# Fall 2023                                                                     #
# Instructor: Dr. Hong Zeng                                                     #
# Contributor to this file: Gilberto Andrés Guerra González                     #
#                                                                               #
######## DOCUMENTATION ##########################################################
#                                                                               #
# is_probably_prime(p, s=5)                                                     #
#   An implementation of the Miller-Rabin primality test.                       #
#                                                                               #
#   p: the possible prime to be tested                                          #
#   s: the number of checks to make; the default of 5 is suitable for 512 bit   #
#      primes and larger                                                        #
#                                                                               #
# ----------------------------------------------------------------------------- #
#                                                                               #
# select_prime(l)                                                               #
#   Selects a random prime (using the cryptographically-suitable secrets        #
#   module).                                                                    #
#                                                                               #
#   l: the length in bits of the prime to be provided                           #
#                                                                               #
# ----------------------------------------------------------------------------- #
#                                                                               #
# eea(a, b)                                                                     #
#   An implementation of the Extended Euclidean Algorithm, directly based on    #
#   what is shown on page 162 of the textbook Understanding Cryptography by     #
#   Christof Paar and Jan Pelzl.                                                #
#                                                                               #   
#   a, b: the two numbers for which to calculate (g, s, t) such that            #
#         g = gcd(a, b) = s * a + t * b                                         #
#                                                                               #   
# ----------------------------------------------------------------------------- #
#                                                                               # 
# to_int(s)                                                                     #
#   Converts the string s to bytes and then to an integer in little-endian      #
#   order.                                                                      #
#                                                                               #
#   s: string to be converted                                                   #
#                                                                               #
# ------------------------------------------------------------------------------#
#                                                                               #
# to_string(i)                                                                  #
#   Converts the integer i to bytes in little-endian order and then to a        #
#   string.                                                                     #
#                                                                               #
#   i: integer to be converted                                                  #
#                                                                               #
# ----------------------------------------------------------------------------- #
#                                                                               #
# rsa_generate_keys(pqlength)                                                   #
#   Generates p and q randomly, sets up the rest of the parameters, and returns #
#   the random public key e and the corresponding private key d.                #
#                                                                               #
#   pqlength: length in bits for each of p and q                                #
#                                                                               #
# ----------------------------------------------------------------------------- #
#                                                                               #
# rsa_encrypt(plaintext, n, e, message_is_int)                                  #
#   Encrypts the plaintext with the public key; this uses the above to_int      #
#   function so a string can be passed as the plaintext.                        #
#                                                                               #
#   plaintext: message to be encrypted                                          #
#   n, e: public key                                                            #
#                                                                               #
# ----------------------------------------------------------------------------- #
#                                                                               #
# rsa_decrypt(ciphertext, n, d, message_is_int)                                 #
#   Decrypts the ciphertext with the private key; this uses the above to_string #
#   function so the numerical plaintext can be converted to the original        #
#   message.                                                                    #
#                                                                               #
#   ciphertext: message to be decrypted                                         #
#   n, d: private key                                                           #   
#                                                                               #
#################################################################################

import secrets
import time

def get_functions():
    def is_probably_prime(p, s=5):
        u = 0
        pminus1 = p - 1
        while pminus1 % 2 == 0:
            pminus1 //= 2
            u += 1
        r = pminus1
        
        for i in range(1, s):
            a = secrets.randbelow(p-2)
            if a <= 2:
                continue
            z = pow(a, r, p)
            if (z != 1) and (z != p - 1):
                for j in range(1, u-1):
                    z = pow(z, 2, p)
                    if z == 1:
                        return False
                if z != p - 1:
                    return False
        return True

    def select_prime(l):
        while True:
            n = pow(2, l) + 2 * secrets.randbits(l - 2) + 1
            if is_probably_prime(n, 5):
                return n


    def eea(a, b):
        r = [a, b] if a > b else [b, a]
        q = [0]
        s = [1, 0]
        t = [0, 1]
        i = 1
        while True:
            i += 1
            r.append(r[i-2] % r[i-1])
            q.append((r[i-2] - r[i]) // r[i-1])
            s.append(s[i-2] - q[i-1] * s[i-1])
            t.append(t[i-2] - q[i-1] * t[i-1])
            if r[i] == 0:
                break
        return (r[i-1], s[i-1], t[i-1])

    def to_int(s):
        return int.from_bytes(s.encode(), byteorder='little')

    def to_string(i):
        n = i.bit_length() // 8 + 1
        return i.to_bytes(n, byteorder='little').decode()

    def rsa_generate_keys(pqlength):
        #print(f'choosing p and q each of bit length {pqlength}, please wait...')
        #begin = time.time()
        p = select_prime(pqlength)
        #got_p = time.time()
        q = select_prime(pqlength)
        #got_q = time.time()

        #print(f'primes p and q chosen in {round(got_p - begin, 2)} and {round(got_q - got_p, 2)} seconds')
        
        n = p * q
        phi_n = (p - 1) * (q - 1)
        while True:
            e = secrets.randbits(pqlength*2)
            gcd = eea(e, phi_n)
            if gcd[0] == 1:
                d = gcd[2]
                break
        return (n, e, d % phi_n)

    def rsa_encrypt(plaintext, n, e, message_is_int):
        return pow(to_int(plaintext) if not message_is_int else int(plaintext), e, n)

    def rsa_decrypt(ciphertext, n, d, message_is_int):
        return to_string(pow(ciphertext, d, n)) if not message_is_int else pow(ciphertext, d, n)

    return rsa_generate_keys, rsa_encrypt, rsa_decrypt

generate_keys, encrypt, decrypt = get_functions()


if __name__ == '__main__':
    print('Generating parameters...\n')

    n, e, d = generate_keys(512)

    print(f'n: {n}\n\n\npublic key: {e}\n\n\nprivate key: {d}')

    while True:
        choice = int(input('\nEncrypt (1), decrypt (2), or exit (3)? '))
        if choice == 1:
            message = input('Enter a message to encrypt > ')
            print(encrypt(message, n, e, False))
        elif choice == 2:
            message = int(input('Enter ciphertext to decrypt > '))
            print(decrypt(message, n, d, False))
        else:
            break
