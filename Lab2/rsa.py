
def generate_rsa_key(p, q, e):
    #Conversion to int
    p=int(p, 16)
    q=int(q, 16)
    e=int(e, 16)

    #First we calculate n and it's totient
    n=p*q
    tot_n_ham = (p-1)*(q-1)
    
    #Determine d by calculating modular inverse
    d = pow(e, -1, tot_n_ham)

    #Return the public key (e, n) and the private key (d, n)
    pub_k = (hex(e), hex(n))
    pri_k= (hex(d), hex(n))
    return pub_k, pri_k

def rsa_encrypt(message, public_key):
    #Conversion to int
    M = int.from_bytes(message.encode(), 'big')   
    e=int(public_key[0], 16)
    n=int(public_key[1], 16)

    #Determine ciphertext and return
    C = hex(pow(M, e, n)).replace('0x', '')
    return C

def rsa_decrypt(ciphertext, private_key):
    #Conversion to int
    C = int(ciphertext, 16)
    d = int(private_key[0], 16)
    n = int(private_key[1], 16)

    #Determine the plaintext M in hex
    M = hex(pow(C, d, n)).replace('0x', '')
    
    #Convert plaintext to ascii string and return
    pt = bytes.fromhex(M).decode("utf-8")
    return pt



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
    n2='DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5'

    #Other test, Result of this should be: C=11
    #M = message , Only needed in encryption function for this one test
    #msg=88
    #e2=hex(7)
    #n=hex(187)

    #Test of decryption
    pub_k = (e2, n2)
    print(rsa_encrypt(msg, pub_k))
    #ct=rsa_encrypt(msg, pub_k)
    #print(ct)
    
    ct = '8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F'
    d2 = '74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D'
    pri_k = (d2, n2)

    print(rsa_decrypt(ct, pri_k))



main()