import math

#Function for Extended Euclidian Algorithm
def egcd(x, y):
    if x == 0:
        return (y, 0, 1)
    
    else:
        g, h, i = egcd(y % x, x)
        return (g, i - (y // x) * h, h)

#Function to get modular inverse
def getModInv(e, p):
    g, h, i = egcd(e, p)
    if g != 1:
        raise Exception("No modular inverse exists")
    else:
        return h % p


def generate_rsa_key(p, q, e):
    
    #Conversion to int
    p=int(p, 16)
    q=int(q, 16)
    e=int(e, 16)

    #First we calculate n and it's totient
    n=p*q
    tot_n_ham = (p-1)*(q-1)
    
    #Select e, Apparently not needed
    #e = math.gcd(tot_n_ham, e)
    
    #Determine d
    d = hex(getModInv(e, tot_n_ham))

    #Return the public key (e, n) and the private key d

    pub_k = (hex(e), hex(n))

    return pub_k, d

def rsa_encrypt(message, public_key):

    M = int.from_bytes(message.encode(), 'big')

    e=int(public_key[0], 16)

    n=int(public_key[1], 16)

    C = pow(M, e) % n

    return hex(C)


def main():

    #Test of keygen. Result of this should be: e=7, n=187, d=23
    #p = hex(17)
    #q = hex(11)
    #e = hex(7)

    #Other test

    p='F7E75FDC469067FFDC4E847C51F452DF'

    q='E85CED54AF57E53E092113E62F436F4F'

    e='0D88C3'

    print(generate_rsa_key(p, q, e))

    #Test of encryption

    msg = "A top secret!"

    e2='010001'

    n='DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5'

    pub_k = (e2, n)

    print(rsa_encrypt(msg, pub_k))



main()