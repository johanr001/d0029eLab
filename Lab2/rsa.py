import hashlib

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
    pt = bytes.fromhex(M).decode("utf-8", errors="replace")
    return pt

def sign_md5_hash(msg, private_key):
    hash = get_hash(msg)
    return rsa_crypt(hash.encode(), (private_key[0], private_key[1]))

def verify_md5_hash(msg, sig, public_key):
    message_hash = get_hash(msg)
    comparison = rsa_crypt(sig, (public_key[0], public_key[1]))
    return comparison == message_hash

# --- Help functions ---

# Like decrypt and encrypt, but without the conversions
def rsa_crypt(input, key):
    text = int(input, 16)
    exponent = int(key[0], 16)
    modulus = int(key[1], 16)

    return hex(pow(text, exponent, modulus)).replace('0x', '')

# Returns hash of given message
def get_hash(message: bytes):
    return hashlib.md5(message).hexdigest().lstrip('0') # Also strips leading zeroes to avoid integer issues

# Tests for task 1
class task1:

    def task1_1():
        #Test of keygen. Result of this should be: e=7, n=187, d=23
        #p = hex(17)
        #q = hex(11)
        #e = hex(7)

        #Other test

        p='F7E75FDC469067FFDC4E847C51F452DF'

        q='E85CED54AF57E53E092113E62F436F4F'

        e='0D88C3'

        print(generate_rsa_key(p, q, e))

    def task1_2():
        #Test of encryption
        msg = "A top secret!"
        e='010001'
        n='DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5'

        #Other test, Result of this should be: C=11
        #M = message , Only needed in encryption function for this one test
        #msg=88
        #e2=hex(7)
        #n=hex(187)

        pub_k = (e, n)
        print(rsa_encrypt(msg, pub_k))
        #ct=rsa_encrypt(msg, pub_k)
        #print(ct)
    
    def task1_3():
        n='DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5'
        #Test of decryption
        
        ct = '8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F'
        d = '74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D'
        pri_k = (d, n)

        print(rsa_decrypt(ct, pri_k))

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

    # Not necessarily asked for, but checks whether or not the verification and signing works
    def task2_4():
        msg = "I owe you $2000."
        p='F7E75FDC469067FFDC4E847C51F452DF'
        q='E85CED54AF57E53E092113E62F436F4F'
        e='0D88C3'

        temp = generate_rsa_key(p, q, e)
        pub_k = temp[0]
        pri_k = temp[1]

        sig = sign_md5_hash(msg.encode(), pri_k)
        if (verify_md5_hash(msg.encode(), sig, pub_k)):
            print("It's working!")
        else:
            print("It's not :(")

def task3():
    # These values are taken from www.y8.com
    e = "10001"
    sig = "1771f92cfcf3b70e3681d180e3818a9159adf78d1f085f8c20c6e20aebc024bdb8553d1052de3fea84a0fabbbeb1b0c1410eec87643112dba83ed95666ef56b037f8e8afaea0c7038e088935a5e2a409f3b1e9f4a4688a38412d4e8fd0722290b4c71efae4606cba954608d594cc578979b7e696259c9b225e2cad88e73e5b7505189621fbff484a82ac8620f9f8a5bc44fc4f43a73865e5e080f878bcf068eb5029f3d28ac5ab04792fde6704c95ee50f0d2b2010c199fb85bff5b156e0dbfd26ab7699fc79b03e2e86507705beebb2d4764a4e83e6c6208c9edbd2f2a3baa9bf69082069049d1ee350c1172a2ef44503ba30a3847e696839dca5729c9f7e83"
    n = "A567708DD0568164151761CDB906D4AD19908C2650379816639254DBD9CC840593ECD3EC081BA0605143487D2BC748969EB42DDA9DC8273B57A19FABF0D60ED40E30CA6F9BB1D1D6A49D323E584E356F4558687117FC3ED85D82A02FB2516CB01A5DB859CE3565C88BA1AF1037FFE39C5DC2491734FF8C2B8B8DF0BC712C930C1D05C4BAC7CDAAC95E7CD1C901F79C03F6FC0A5DF4DA7BE6DB764270EBF44D22DA00776FD6C95F17FDDA752EA5570CF6EA5CB6E073A568CFA174E275827E109FC1F5A2EB01E938B10A44CCD3C289F54935820A34B31CE988C2474E820E0A36F0474F8AF1290475DACDE19A5CFF5E9D9895BA9A43D04AA21705010430D332B38F"
    hash = "c6cf9f19fd74ebece68a2a210a6b4385dad760c60415f7615671284ee28712f6"

    verify = rsa_crypt(sig, (e, n))
    verify = verify[-len(hash):]    # Removes everything but the hash
    if (hash == verify):
        print ("It's working!")
    else:
            print("It's not :(")

def task4():
    p='F7E75FDC469067FFDC4E847C51F452DF'
    q='E85CED54AF57E53E092113E62F436F4F'
    e='0D88C3'

    temp  = generate_rsa_key(p, q, e)
    pub_k  = temp[0]
    pri_k  = temp[1]

    with open("./Lab2/hello.pyc", "rb") as f:
        ben_data = f.read()

    with open("./Lab2/goodbye.pyc", "rb") as f:
        mal_data = f.read()

    sig = sign_md5_hash(ben_data, pri_k)

    if (verify_md5_hash(mal_data, sig, pub_k)):
        print("It's working!")
    else:
        print("It's not :(")
    

def main():
    task2.task2_1()
    task2.task2_2()
    task2.task2_4()
    task3()
    task4()

if __name__ == "__main__":
    main()