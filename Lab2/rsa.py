
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

# Like decrypt and encrypt, but without the conversions
def rsa_crypt(input, key):
    text = int(input, 16)
    exponent = int(key[0], 16)
    modulus = int(key[1], 16)

    return hex(pow(text, exponent, modulus)).replace('0x', '')

# Runs all the tests belonging to task 2
class task2:

    def task2_1():
        msg1 = "I owe you $2000."
        msg2 = "I owe you $3000."
        p='F7E75FDC469067FFDC4E847C51F452DF'
        q='E85CED54AF57E53E092113E62F436F4F'
        e='0D88C3'

        pri_k  = generate_rsa_key(p, q, e)[1]

        print("Sign 1 = ", rsa_encrypt(msg1, pri_k),"\n")
        print("Sign 2 = ", rsa_encrypt(msg2, pri_k))

    def task2_2():
        msg = "Launch a missile." # Not used
        sig = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"
        sig_cor = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F"
        e = "010001"
        n = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"

        print("Normal in ASCII: ", rsa_decrypt(sig, (e, n)), "\n")
        print("Normal in hexadecimal: ", rsa_crypt(sig, (e, n)), "\n")
        print("Corrupted signature in hexadecimal: ", rsa_crypt(sig_cor, (e, n)))



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



if __name__ == "__main__":
    main()