import math

#Function for Extended Euclidian Algorithm
def egcd(x, y):
    if x == 0:
        return (y, 0, 1)
    
    else:
        g, h, i = egcd(y % x, x)
        return (g, i - (y // x) * h, h)

#Function to do modular inverse
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

    pub_k = (e, n)

    return pub_k, d



def main():

    #Test of keygen. Result of this should be: e=7, n=187, d=23
    p = 17
    q = 11
    e = 7

    #Other test

    #p=int('F7E75FDC469067FFDC4E847C51F452DF', 16)

    #q=int('E85CED54AF57E53E092113E62F436F4F', 16)

    #e=int('0D88C3', 16)

    print(generate_rsa_key(p, q, e))

main()
