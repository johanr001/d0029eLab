import math

#Function for Extended Euclidian Algorithm
def egcd(x, y):
    if x == 0:
        return (y, 0, 1)
    
    else:
        g, h, i = egcd(y % x, x)
        return (g, i - (y // x) * h, h)

def modInv(e, p):
    g, h, i = egcd(e, p)
    if g != 1:
        raise Exception("No modular inverse exists")
    else:
        return h % p


def generate_rsa_key(p, q, e):
    
    #First we calculate n and it's totient
    n=p*q
    tot_n_ham = (p-1)*(q-1)
    
    #Select e, Apparently not needed
    #e = math.gcd(tot_n_ham, e)
    
    #Determine d
    d = modInv(e, tot_n_ham)

    #Return the public key (e, n) and the private key d
    return e, n, d

def main():

    #Test of keygen
    p = 17

    q = 11

    e = 7

    print(generate_rsa_key(p, q, e) , "Result should be: e=7, n=187, d=23")

main()
