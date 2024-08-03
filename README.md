# RSA
RSA Encryption &amp; Decryption Implementation

The three commands below specify the exact command-line syntax for invoking encryption and decryption.
	
 	1. python3 rsa.py -g p.txt q.txt
	2. python3 rsa.py -e message.txt p.txt q.txt encrypted.txt
	3. python3 rsa.py -d encrypted.txt p.txt q.txt decrypted.txt

An explanation of the command-line syntax is as follows:

• For Key Generation (indicated by ‘-g’ in line 1)

– The generated values of p and q will be written to p.txt and q.txt respectively.

– The .txt files should contain the number as an integer represented in ASCII.

• For Encryption (indicated by ‘-e’ in line 2)

– Given the p and q values found in p.txt and q.txt respectively, encrypt the plaintext message in message.txt using the RSA algorithm, and write the output to encrypted.txt
 
 – The key generation step mentioned in the previous bullet is there to simply make you aware of the necessity in real world applications. 

• For Decryption (indicated by ’-d’ in line 3)

– Given the p and q values found in p.txt and q.txt respectively, decrypt the ciphertext in encrypted.txt using the RSA algo- rithm, and write the output to decrypted.txt

 Note: The priority in RSA is to select a particular value of e and then choose p and q accordingly. For this implementation I used e = 65537, but feel free to change this prime number.
