import random
import math

# Teste miller rabin para ver se o número é primo
def millerRabin(d, n):
    a = 2 + random.randint(1, n - 4)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True;
    
    while d != n - 1:
        x = (x * x) % n;
        d *= 2;
        if x == 1:
            return False;
        if x == n - 1:
            return True;
    return False;
 

def ePrimo(n, k): 
    if (n <= 1 or n == 4):
        return False;
    if (n <= 3):
        return True;
    
    d = n - 1;
    while d % 2 == 0:
        d //= 2;
    for i in range(k):
        if millerRabin(d, n) == False:
            return False;
    return True;

# Gerador de chaves (P e Q com 1024 bits)
def gerarChaves():
    primos = []
    for i in range(2):
        po = False
        while po == False:
            n = random.getrandbits(1024)
            po = ePrimo( n, 4)
        primos.append(n)
    
    p = primos[0]
    q = primos[1] 
    n = p * q;
    z = (p - 1) * (q - 1);
        
    while True:
        e = random.randrange(2 ** (1024 - 1), 2 ** (1024))
        if math.gcd(e, z) == 1:
            break 
             
    d = pow(e, -1, z)
    publicKey = (n, e)
    privateKey = (n, d)
    
    return publicKey, privateKey

# Cifrador/decifrador
def cifradorDecifrador(texto, chave, n):
    res = pow(texto, chave, n)
    return res
