/*************************************************************************************************************************
 *
 * NAME
 *    otp_dec.c 
 * SYNOPSIS
 *    Client program for One-Time Pad decryption.
 * DESCRIPTION
 *    Reads and validates the text in the ciphertext and key text files. 
 *    Then attempts to connect to the decryption server daemon, send the ciphertext and key for decryption, and 
 *       receive back the decrypted text to print to the screen.
 * INSTRUCTIONS
 *    Use the included compileall script to compile this program as well as the other four programs.
 *    Make sure the decryption daemon server is running and listening on the target port before running this program.
 *    Then start this program by using the command line:
 *       otp_dec CIPHERTEXT KEY PORT
 *    If successful the decrypted text will be printed to stdout.
 * AUTHOR
 *    Written by Andrew Swaim
 *
*************************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

typedef enum { false, true } bool; // Create bool type for C89/C99 compilation.

#define ID_LEN 7 // Number of characters to send for this client's id (in the format "otp_xxx")
#define AUTH_LEN 4 // Number of characters to receive for the server's authorization
#define BUF_LEN 9 // Number of digits (characters) to send for the length of the next transmission (int up to 9 digits)
#define DEBUG false // Turn this on to true to enable debug mode

/*************************************************************************************************************************
 * Function Declarations
*************************************************************************************************************************/

int scanfile(char*); // To get a file content's length up to the newline and validate bad characters
void readfile(char*, char*, int); // To get the content of a file up to the newline character
int sendrecv(int, char*, int, bool); // To send or receive data to or from a server

/*************************************************************************************************************************
 * Main 
*************************************************************************************************************************/

int main(int argc, char *argv[]) {

    int sockFD, port, chars, textLen, keyLen;
    struct sockaddr_in addr;
    struct hostent* host;
    char id[ID_LEN+1] = "otp_dec"; // To send to the server for authentication
    char auth[AUTH_LEN+1]; // To receive an authentication response from the server

    if (argc != 4) { fprintf(stderr, "USAGE: %s <ciphertext> <key> <port>\n", argv[0]); exit(1); } // Check usage & args

    // Get and validate port number
    port = atoi(argv[3]);
    if (port < 0 || port > 65535) { fprintf(stderr, "otp_dec: ERROR, invalid port %d\n", port); exit(2); }
    if (port < 50000) { printf("otp_dec: WARNING, recommended to use a port number above 50000\n"); }
    if (DEBUG) { printf("DEBUG: using port: %d\n", port); } // DEBUG

    // Get the length of the files (up to the newline character) and validate their contents
    if ((textLen = scanfile(argv[1])) < 1) { fprintf(stderr, "otp_dec: ERROR, ciphertext file cannot be empty\n"); exit(1); } 
    if ((keyLen = scanfile(argv[2])) < 1) { fprintf(stderr, "otp_dec: ERROR, key file cannot be empty\n"); exit(1); }

    // Make sure the key file is longer than the ciphertext file
    if (keyLen < textLen) { fprintf(stderr, "otp_dec: ERROR, key \'%s\' is too short\n", argv[2]); exit(1); }

    // Get the contents of the ciphertext file
    char ciphertext[textLen+1]; // +1 for the ending null character
    readfile(argv[1], ciphertext, sizeof(ciphertext));
    if (DEBUG) { printf("DEBUG: ciphertext file contents read: %s\n", ciphertext); } // DEBUG

    // Get the contents of the key file
    char key[keyLen+1];
    readfile(argv[2], key, sizeof(key));
    if (DEBUG) { printf("DEBUG: key file contents read: %s\n", key); } // DEBUG

    // Set up the server address struct 
    memset((char*)&addr, '\0', sizeof(addr)); // Clear out the address struct
    addr.sin_family = AF_INET; // Create a network-capable socket
    addr.sin_port = htons(port); // Store the port number

    // Get the server host info, converting the machine name into a special form of address
    if ((host = gethostbyname("localhost")) == NULL) {
        fprintf(stderr, "otp_dec: ERROR, no such host\n"); exit(2); 
    }
    memcpy((char*)&addr.sin_addr.s_addr, (char*)host->h_addr, host->h_length); // Copy host info to address
    if (DEBUG) { printf("DEBUG: host info processed\n"); } // DEBUG

    // Create and set up the socket
    if ((sockFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "otp_dec: ERROR opening socket\n"); exit(2); 
    }
    if (DEBUG) { printf("DEBUG: socket FD setup: %d\n", sockFD); } // DEBUG

    // Connect socket to address in order to connect to the server
    if (connect(sockFD, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "otp_dec: ERROR connecting\n"); exit(2);
    }
    if (DEBUG) { printf("DEBUG: sending id to server: %s\n", id); } // DEBUG

    // Send id to server for authorization
    if ((chars = sendrecv(sockFD, id, ID_LEN, true)) != ID_LEN) {
        fprintf(stderr, "otp_dec: ERROR, only %d chars of id were sent to server on port %d\n", chars, port);
    }

    // Receive authorization response from server
    if ((chars = sendrecv(sockFD, auth, AUTH_LEN, false)) != AUTH_LEN) {
        fprintf(stderr, "otp_dec: ERROR, only %d chars of auth were received from server on port %d\n", chars, port);
    }
    if (DEBUG) { printf("DEBUG: received auth from server: %s\n", auth); } // DEBUG

    // Evaluate authorization
    if (strcmp(auth, "PASS") != 0) { 
        fprintf(stderr, "otp_dec: ERROR, could not contact or authenticate with otp_dec_d on port %d\n", port); 
        exit(2);
    }
    else { // If authorization passed

        // Send the ciphertext file length, up to 9 digits
        char textLenBuf[BUF_LEN+1];
        memset(textLenBuf, '\0', sizeof(textLenBuf));
        snprintf(textLenBuf, sizeof(textLenBuf), "%d", textLen); // Convert from int to string
        if ((chars = sendrecv(sockFD, textLenBuf, BUF_LEN, true)) != BUF_LEN) {
            fprintf(stderr, "otp_dec: ERROR, only %d chars of textLen were sent to server on port %d\n", chars, port);
        }
        if (DEBUG) { printf("DEBUG: text length sent to server: %s\n", textLenBuf); } // DEBUG

        // Send ciphertext file contents
        if ((chars = sendrecv(sockFD, ciphertext, textLen, true)) != textLen) {
            fprintf(stderr, "otp_dec: ERROR, only %d chars of ciphertext were sent to server on port %d\n", chars, port);
        }
        if (DEBUG) { printf("DEBUG: ciphertext contents sent to server: %s\n", ciphertext); } // DEBUG

        // Send key file length
        char keyLenBuf[BUF_LEN+1];
        memset(keyLenBuf, '\0', sizeof(keyLenBuf));
        snprintf(keyLenBuf, sizeof(keyLenBuf), "%d", keyLen);
        if ((chars = sendrecv(sockFD, keyLenBuf, BUF_LEN, true)) != BUF_LEN) {
            fprintf(stderr, "otp_dec: ERROR, only %d chars of keyLen were sent to server on port %d\n", chars, port);
        }
        if (DEBUG) { printf("DEBUG: key length sent to server: %s\n", keyLenBuf); } // DEBUG

        // Send the key file contents
        if ((chars = sendrecv(sockFD, key, keyLen, true)) != keyLen) {
            fprintf(stderr, "otp_dec: ERROR, only %d chars of key were sent to server on port %d\n", chars, port);
        }
        if (DEBUG) { printf("DEBUG: key contents sent to server: %s\n", key); } // DEBUG

        // Receive decrypted plaintext back
        char plaintext[textLen+1];
        if ((chars = sendrecv(sockFD, plaintext, textLen, false)) != textLen) {
            fprintf(stderr, "otp_dec: ERROR, only %d chars of encryption were recevied from server on port %d\n", chars, port);
        }

        // Print decryption result
        printf("%s\n", plaintext);
    }

    close(sockFD); // Close the socket
    return 0;
}

/*************************************************************************************************************************
 * Function Definitions 
*************************************************************************************************************************/

/*
 * Get the length of a file's contents up to the newline character, and also check that there are no bad characters
 * char* filename: the name of the file to scan
*/ 
int scanfile(char* filename) {

    FILE* fd; // File descriptor
    int length = 0; // Length of the file (not including the newline)
    char c; // Character to be processed

    // Try to open the file
    if ((fd = fopen(filename, "r")) == NULL) { fprintf(stderr, "otp_dec: ERROR, opening file \'%s\'\n", filename); exit(1); }
    if (DEBUG) { printf("DEBUG: file \'%s\' opened for scanning\n", filename); } // DEBUG

    // Loop through each character in the file until a newline is reached
    while ((c = fgetc(fd)) != '\n') { 
        
        if (DEBUG) { printf("DEBUG: character retrieved from file: %c\n", c); } // DEBUG
        if (c == ' ' || (c >= 'A' || c <= 'Z')) { length++; } // If valid increase the count
        else { fprintf(stderr, "otp_dec: ERROR, \'%s\' contains bad characters\n", filename); exit(1); }
    }

    fclose(fd); // Close the file
    if (DEBUG) { printf("DEBUG: file \'%s\' closed after scanning\nlength to return: %d\n", filename, length); } // DEBUG
    return length; // Return the length of the file
}

/*
 * Get and store the contents of a file up to the ending newline character
 * char* filename: the name of the file
 * char* str: the string container to hold the contents of the file
 * int len: the length of the content to get up to the newline character (as discovered by scanfile())
*/
void readfile(char* filename, char* str, int len) {

    FILE* fd; // File descriptor

    memset(str, '\0', len); // Clear the string
    if ((fd = fopen(filename, "r")) == NULL) { fprintf(stderr, "otp_dec: ERROR, opening file \'%s\'\n", filename); exit(1); }
    fgets(str, len, fd); // Store the contents
    fclose(fd); // Close the file
}

/*
 * Send or receive data to or from a socket file descriptor
 * int sockFD: the socket file descriptor the client is connected to the server on
 * char* str: the string with the data to send or to hold the data that is received
 * int len: the length of the data to send or receive
 * bool sendMode: true for sending data, false for receiving data
*/
int sendrecv(int sockFD, char* str, int len, bool sendMode) {

    int total = 0; // To calculate the total chars that get sent/received
    int rem = len; // To calculate how many chars are left to send/receive
    int n;      // To hold how many chars get sent with each send()/recv() call

    // If receiving, clear buffer
    if (!sendMode) { memset(str, '\0', len+1); }

    // Loop to ensure that all data is sent or received
    while (total < len) {

        if (sendMode) { n = send(sockFD, str+total, rem, 0); }
        else { n = recv(sockFD, str+total, rem, 0); }
        if (n == -1) { break; }
        total += n;
        rem -= n;
        if (DEBUG) { printf("DEBUG: bytes sent/recv: %d\nbytes total: %d\nbytes rem:%d\n", n, total, rem); } // DEBUG
    }

    if (DEBUG) { printf("DEBUG: total bytes sent/recv: %d out of %d\n", total, len); } // DEBUG
    return total;
}

