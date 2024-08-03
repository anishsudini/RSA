import sys
from BitVector import *
import random

class RSA ():
    def __init__(self, e) -> None :
        self.e = e

        self.bits = 128
        self._largest = (1 << self.bits) - 1

        p_file = open('p.txt', 'r')
        self.p = int(p_file.read())
        p_file.close()
        
        q_file = open('q.txt', 'r')
        self.q = int(q_file.read())
        q_file.close()

        self.n = self.p * self.q
        self.totient_n = (self.p - 1) * (self.q - 1)
        self.bv_e = BitVector(intVal = self.e)
        self.d = (self.bv_e.multiplicative_inverse(BitVector(intVal = self.totient_n))).int_val()
        
        self.candidate = None

    def set_initial_candidate(self):                                         
        candidate = random.getrandbits( self.bits )                          
        if candidate & 1 == 0: candidate += 1                                
        candidate |= (1 << self.bits-1)                                     
        candidate |= (2 << self.bits-3)                                     
        self.candidate = candidate                         

    def set_probes(self):                                                    
        self.probes = [2,3,5,7,11,13,17]                                   

    def test_candidate_for_prime(self):                                      
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                         
        if p == 1: return 0                                           
        if p in self.probes:                                          
            self.probability_of_prime = 1                                 
            return 1                                                        
        if any([p % a == 0 for a in self.probes]): return 0                 
        k, q = 0, self.candidate-1                                       
        while not q&1:                                                    
            q >>= 1                                                      
            k += 1                                                         

        for a in self.probes:                                           
            a_raised_to_q = pow(a, q, p)                                    
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue        
            a_raised_to_jq = a_raised_to_q                                   
            primeflag = 0                                                   
            for j in range(k-1):                                            
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                  
                if a_raised_to_jq == p-1:                                   
                    primeflag = 1                                         
                    break                                                   
            if not primeflag: return 0                                       
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))       
        return self.probability_of_prime                                     

    def findPrime(self):                                                    
        self.set_initial_candidate()                                     
        
        self.set_probes()                                                 

        max_reached = 0                                                     
        while 1:                                                             
            if self.test_candidate_for_prime():                             
                break                                                       
            else:                                                          
                if max_reached:                                             
                    self.candidate -= 2                                    
                elif self.candidate >= self._largest - 2:                   
                    max_reached = 1                                       
                    self.candidate -= 2                                      
                else:                                                        
                    self.candidate += 2                                      
        return self.candidate
    
    def p_q_gen(self, ptext:str, qtext:str) -> None :
        self.p = None
        self.q = None

        temp = True
        while(temp):
            cond1 = False
            cond2 = False

            self.findPrime()
            bv = BitVector(intVal = self.candidate, size=128)

            if(bv[126] == 1 and bv[127] == 1):
                cond1 = True

            bv_1 = BitVector(intVal = (self.candidate - 1), size=128)
            if(((bv_1.gcd(self.bv_e)).int_val()) == 1):
                cond2 = True

            if(cond1 and cond2):
                self.p = self.candidate
                temp = False
            
        temp = True
        while(temp):
            cond1 = False
            cond2 = False
            cond3 = False

            self.findPrime()
            bv = BitVector(intVal = self.candidate, size=128)

            if(bv[126] == 1 and bv[127] == 1):
                cond1 = True

            if(self.p != self.candidate):
                print("Passed Equality check")
                cond2 = True

            bv_1 = BitVector(intVal = (self.candidate - 1), size=128)
            if(((bv_1.gcd(self.bv_e)).int_val()) == 1):
                cond3 = True

            if(cond1 and cond2 and cond3):
                self.q = self.candidate
                temp = False
            

        p_file = open(ptext, 'w')
        p_file.write(str(self.p))
        p_file.close()

        q_file = open(qtext, 'w')
        q_file.write(str(self.q))
        q_file.close()

    def encrypt(self, plaintext:str, ciphertext:str) -> None :
        bv = BitVector(filename = plaintext)
        encrypted_file = open(ciphertext, "w")

        while(bv.more_to_read):
            M = bv.read_bits_from_file(128)
            
            if(M.length() < 128):
                M.pad_from_right(128 - M.length())

            M.pad_from_left(128)

            C = pow(M.int_val(), self.e, self.n)
            C_hex = BitVector(intVal = C, size=256).get_bitvector_in_hex()
            encrypted_file.write(C_hex)
        
        encrypted_file.close()
    
    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None :
        with open(ciphertext, 'r') as file:
            hex_string = file.read().strip()

        binary_string = ''.join(format(int(hex_char, 16), '04b') for hex_char in hex_string)

        plaintext_file = open(recovered_plaintext, "w")

        index = 0
        while index < len(binary_string):
            C = BitVector(bitstring=binary_string[index:index+256])
            index += 256

            V_p = pow(C.int_val(), self.d, self.p)
            V_q = pow(C.int_val(), self.d, self.q)
            
            bv_q = BitVector(intVal = self.q)
            bv_p = BitVector(intVal = self.p)
            q_MI_mod_p = bv_q.multiplicative_inverse(bv_p).int_val()
            p_MI_mod_q = bv_p.multiplicative_inverse(bv_q).int_val()

            X_p = self.q * q_MI_mod_p
            X_q = self.p * p_MI_mod_q

            M = BitVector(intVal = (((V_p * X_p) + (V_q * X_q)) % self.n), size=128)
            plaintext_file.write(M.get_text_from_bitvector())
        
        plaintext_file.close()

if __name__ == "__main__":
    cipher = RSA(e = 65537)

    if sys.argv[1] == "-g":
        cipher.p_q_gen(ptext = sys.argv[2], qtext = sys.argv[3])
    
    elif sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[5])
    
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], recovered_plaintext = sys.argv[5])
