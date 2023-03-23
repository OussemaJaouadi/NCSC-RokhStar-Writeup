from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import functools

flag = "Securinets{REDACTED}"
flag = flag.encode()
flag = pad(flag,16)


ITERS = int(6e7)

def xor(a:bytes,b:bytes):
    s = b''
    for (i,j) in zip(a,b):
        s+=long_to_bytes(i^j)
    return s

@functools.cache
def gen_function(i):
    if i == 0: return 1
    if i == 1: return 2
    if i == 2: return 3
    if i == 3: return 4
    return -44574*gen_function(i-4) +5767*gen_function(i-3) + 427*gen_function(i-2) - 19*gen_function(i-1)


def gen_key(k):
    k = str(k)
    k1,k2 = k[:len(k)//2],k[len(k)//2+1:]
    k1 = hashlib.sha256(k1.encode()).digest()
    k2 = hashlib.sha256(k2.encode()).digest()
    k = xor(k1,k2)
    return k[:16],k[16:]

k =gen_function(ITERS)
iv,k =gen_key(k)
aes = AES.new(key=k,iv=iv,mode=AES.MODE_CBC)

flag = aes.encrypt(flag)

with open('out.txt','w') as f :
    f.write(flag)

f.close()