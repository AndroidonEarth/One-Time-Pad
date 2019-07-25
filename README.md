# One-Time-Pad
Server Daemons and Clients for performing One-Time Pad cipher encryption and decryption

# One-Time Pad Ciphering Definition
https://en.wikipedia.org/wiki/One-time_pad

**Plaintext** is the term for the information that you wish to encrypt and protect. It is *human readable*.

**Ciphertext** is the term for the plaintext after it has been encrypted by the programs. Ciphertext is *not human-readable*, and in fact cannot be cracked, if the OTP system is used correctly.

A **Key** is the random sequence of characters that will be used to convert Plaintext to Ciphertext, and back again. It must not be re-used, or else the encryption is in danger of being broken.

The following excerpt from the above Wikipedia article was captured on 2/21/2015:

*“Suppose Alice wishes to send the message "HELLO" to Bob. Assume two pads of paper containing identical random sequences of letters were somehow previously produced and securely issued to both. Alice chooses the appropriate unused page from the pad. The way to do this is normally arranged for in advance, as for instance 'use the 12th sheet on 1 May', or 'use the next available sheet for the next message'.*

*The material on the selected sheet is the key for this message. Each letter from the pad will be combined in a predetermined way with one letter of the message. (It is common, but not required, to assign each letter a numerical value, e.g., "A" is 0, "B" is 1, and so on.)*

*In this example, the technique is to combine the key and the message using modular addition. The numerical values of corresponding message and key letters are added together, modulo 26. So, if key material begins with "XMCKL" and the message is "HELLO", then the coding would be done as follows:*

          H       E       L       L       O  message
       7 (H)   4 (E)  11 (L)  11 (L)  14 (O) message
    + 23 (X)  12 (M)   2 (C)  10 (K)  11 (L) key
    = 30      16      13      21      25     message + key
    =  4 (E)  16 (Q)  13 (N)  21 (V)  25 (Z) message + key (mod 26)
          E       Q       N       V       Z  → ciphertext

*If a number is larger than 26, then the remainder, after subtraction of 26, is taken [as the result]. This simply means that if the computations "go past" Z, the sequence starts again at A.*

*The ciphertext to be sent to Bob is thus "EQNVZ". Bob uses the matching key page and the same process, but in reverse, to obtain the plaintext. Here the key is subtracted from the ciphertext, again using modular arithmetic:*

           E       Q       N       V       Z  ciphertext
        4 (E)  16 (Q)  13 (N)  21 (V)  25 (Z) ciphertext
    -  23 (X)  12 (M)   2 (C)  10 (K)  11 (L) key
    = -19       4      11      11      14     ciphertext – key
    =   7 (H)   4 (E)  11 (L)  11 (L)  14 (O) ciphertext – key (mod 26)
           H       E       L       L       O  → message

*Similar to the above, if a number is negative then 26 is added to make the number zero or higher.*

*Thus Bob recovers Alice's plaintext, the message "HELLO". Both Alice and Bob destroy the key sheet immediately after use, thus preventing reuse and an attack against the cipher.”*

# The Four Main Network Programs
This project contains four main network programs; 1 **encryption client**, 1 **encryption daemon**, 1 **decryption client**, and 1 **decryption daemon** (as well as a fifth *utility* program called **keygen** for generating key files).

The four network programs work in the same exact fashion as above to perform One-Time Pad ciphering, except using **modulo 27** operations instead *(26 capital letters and the space character)*.

The two daemons run in the background listening for connections on a particular port. If a corresponding client successfully connects to a daemon on the socket and is authenticated, the clients will read and validate the text and key files and send the information over to the daemons, where the daemons will do the encryption or decryption work and send the results back to the clients for them to print to the screen.

# Instructions
Use the included **compileall** script to compile the five programs.

Then use the **keygen** utility to generate a key file by using the command:

    keygen KEYLENGTH > [KEYFILE]
 
where KEYLENGTH is the length of the key in characters, and KEYFILE is the text file to store the key. Be sure that the key is AT LEAST as long as the text it will be used to encrypt or decrypt *(this will also be validated when they are read in by the clients)*. 
 
Then start the daemons in the background by running:

    otp_enc_d PORT1 &
    otp_dec_d PORT2 &
    
where PORT1 and PORT2 are two different port numbers that the daemons should listen for connections on. Valid port options are port **numbers between 0 and 65535** - although it is recommended to use port **numbers above 50000** as well.

Then start whichever client you want (whether you want to encrypt or decrypt text) by running:

    otp_enc PLAINTEXT KEY PORT1
    
or

    otp_dec CIPHERTEXT KEY PORT2
    
where PLAINTEXT or CIPHERTEXT are the text files you want to encrypt or decrypt, KEY is the key used for the One-Time Pad cipher, and PORT1 or PORT2 are the same port numbers that the corresponding daemons are listening on.

If successful, the encrypted or decrypted text will be printed to **stdout**.
