import random
import math
import hashlib
from binascii import hexlify

class OAEPERSA:
    #por volta de 96 caracteres de texto por bloco
    tamanho = 1024
    k = 20
    k0 = 24
    k1 = 24

    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.z = None
        self.e = None
        self.d = None
        self.dp = None
        self.dq = None
        self.qinv = None
        self.chavePublica = None
        self.chavePrivada = None
        


    def millerRabin(self, d, n):
        a = 2 + random.randint(1, n - 4)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        
        while d != n - 1:
            x = (x * x) % n
            d *= 2
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False
    

    def ePrimo(self, n, k):  
        if (n <= 1 or n == 4):
            return False
        if (n <= 3):
            return True
        
        d = n - 1;
        while d % 2 == 0:
            d //= 2
        for i in range(k):
            if self.millerRabin(d, n) == False:
                return False
        return True

    def gerarChaves(self):
        primos = []
        for i in range(2):
            po = False
            while po == False:
                n = random.getrandbits(1024)
                po = self.ePrimo( n, 4)
            primos.append(n)
        
        self.p = primos[0]
        self.q = primos[1] 
        self.n = self.p * self.q
        self.z = (self.p - 1) * (self.q - 1)
            
        while True:
            self.e = random.randrange(2 ** (1024 - 1), 2 ** (1024))
            if math.gcd(self.e, self.z) == 1:
                break 
                
        self.d = pow(self.e, -1, self.z)
        
        self.chavePublica = (self.n, self.e)
        self.chavePrivada = (self.n, self.d)
        
        self.dp = self.d % (self.p-1)
        self.dq = self.d % (self.q-1)
        
        self.qinv = pow(self.q,-1,self.p)
        
        return None
    
    def cifradorDecifrador(self, texto, chave, n):
        res = pow(texto, chave, n)
        
        return res
    
    
    def oString(self, x, tamanho):
        res = b"".join([chr((x >> (8 * i)) & 0xFF).encode() for i in reversed(range(tamanho))])
        return res

    def mascara(self, m, tamanho):
        cont = 0
        saida = b""
        while len(saida) < tamanho:
            C = self.oString(cont, 4)
            saida = saida + hashlib.sha256(m + C).digest()
            cont += 1
            
        return saida[:tamanho] 
    
    
    
    
    
    def cifradorOAEP(self, m):
        m = m << OAEPERSA.k1
        
        r = random.randint(2**(OAEPERSA.k0-1),2**OAEPERSA.k0)
        rs = str(r)
        rs = hexlify(self.mascara(rs.encode(),(OAEPERSA.tamanho - OAEPERSA.k0) // 8))
        
        x = m^int(rs,16)
        xs = str(x)
        xs = hexlify(self.mascara(xs.encode(), OAEPERSA.k0 // 8))
        
        y = r^int(xs,16)

        return self.cifradorDecifrador((x << OAEPERSA.k0) | y, self.e, self.n)

    def decifradorOAEP(self, c):

        m1 = pow(c,self.dp,self.p)
        m2 = pow(c,self.dq,self.q)
        h = self.qinv * (m1 - m2)
        m = (m2 + h * self.q) % self.n
        
        x = m >> OAEPERSA.k0
        Y = m % x

        xs = str(x)
        xs = hexlify(self.mascara(xs.encode(), OAEPERSA.k0 // 8))
        r = Y^int(xs,16)

        rs = str(r)
        rs = hexlify(self.mascara(rs.encode(),(OAEPERSA.tamanho - OAEPERSA.k0) // 8))
        res = x^int(rs,16)
        res = res >> OAEPERSA.k1

        return res

    def cifradorTxt(self, texto):
        m = ""
        for i in texto:
            j = str(ord(i))
            while len(j) < 3:
                j = "0" + j
            m += j
            
        m = int(m)
        tam = len(bin(m)) - 2
        mEnch = m << (OAEPERSA.tamanho - OAEPERSA.k0 - OAEPERSA.k1 - tam)
        mEnch = mEnch^(2**(OAEPERSA.tamanho - OAEPERSA.k0 - OAEPERSA.k1 - tam - 1))
        
        return self.cifradorOAEP(mEnch)

    def decifradorTxt(self, c):
        mEnch = self.decifradorOAEP(c)
        t = str(bin(mEnch))
        t = t.rstrip('0')
        t = t[:-1]
        n = int(t, 2)
        res = ""
        while n > 0:
            c = n % 1000
            res = res + chr(c)
            n = n // 1000
            
        return res[::-1]

