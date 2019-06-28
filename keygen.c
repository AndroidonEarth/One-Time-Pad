/*************************************************************************************************************************
 * 
 * NAME
 *    keygen.c - One-Time Pad encryption/decryption key generator
 * SYNOPSIS
 *    Creates a key file of specified length, containing 27 possible characters (A-Z and the space character).
 *    The key is output to stdout w/ +1 length as a newline will also be appended.
 * INSTRUCTIONS
 *    keygen is automatically compiled along with the other 4 programs using the compileall script.
 *    The syntax for keygen is as follows:
 *       keygen KEYLENGTH > [KEYFILE]
 *    where KEYLENGTH is the length of the key file in characters, and KEYFILE is the text file to store the key.
 * AUTHOR
 *    Written by Andrew Swaim
 *
*************************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MIN_CHAR 64 // The minimum integer value of a character to be randomly generated ('@', to be replaced by space)
#define MAX_CHAR 90 // The maximum integer value of a character to be randomly generated ('Z')

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[]) {

    char c;
    int i, keylength;

    if (argc != 2) { fprintf(stderr, "USAGE: %s keylength\n", argv[0]); exit(1); } // Check usage & args
    keylength = atoi(argv[1]); // Get the keylength
    if (keylength < 1) { fprintf(stderr, "KEYGEN: keylength must be greater than 0\n"); exit(1); } // Validate keylength

    // Seed the random number generator
    unsigned seed = time(0);
    srand(seed);

    // Generate the key
    for (i = 0; i < keylength; i++) {

        c = (char)(rand() % (MAX_CHAR - MIN_CHAR + 1) + MIN_CHAR); // Generate a random character
        if (c == '@') { c = ' '; } // Replace '@' w/ ' '
        printf("%c", c); // Print to stdout
    }
    printf("\n"); // Add a newline character

    return 0;    
}
