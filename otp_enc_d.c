/*************************************************************************************************************************
 *
 * NAME
 *    otp_enc_d.c 
 * SYNOPSIS
 *    Daemon for One-Time Pad encryption.
 * DESCRIPTION
 *    Runs in the background as a daemon, listening on the particular port/socket for encryption clients to try to 
 *       connect (supports up to five concurrent socket connections running at the same time).
 *    If an encryption client connects and is authenticated, a new child process is spawned where the daemon will then 
 *       try to receive the plaintext and key from the client, encrypt the text, and send the encrypted text back to 
 *       the client.
 * INSTRUCTIONS
 *    Use the included compileall script to compile this program as well as the other four programs.
 *    Then start this program running in the background by using the command:
 *       otp_enc_c PORT &
 *    If successful, this daemon will run in the background listening for connections forever until its manually killed.
 * AUTHOR
 *    Written by Andrew Swaim
 *
*************************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

typedef enum { false, true } bool; // Create bool type for C89/C99 compilation.

#define ID_LEN 7 // Number of characters to receive for client id (in the format "otp_xxx")
#define AUTH_LEN 4 // Number of characters to send for authorization ("PASS" or "FAIL")
#define BUF_LEN 9 // Number of digits (characters) to receive for the length of the next transmission (int up to 9 digits)
#define DEBUG false // Turn this on to true to enable debug mode

/*************************************************************************************************************************
 * Function Declarations
*************************************************************************************************************************/

int sendrecv(int, char*, int, bool); // To send or receive data to or from a client
void encrypt(char*, char*, char*, int); // To encrypt the plaintext received from a client

/*************************************************************************************************************************
 * Main 
*************************************************************************************************************************/

int main(int argc, char *argv[]) {

    int listeningFD, connectedFD, port, chars, textLen, keyLen, status;
    socklen_t clientSize;
    struct sockaddr_in server, client;
    pid_t pid;
    char id[ID_LEN+1]; // Client ID for authrization
    char auth[AUTH_LEN+1]; // Authorization result to send to client
    
    if (argc != 2) { fprintf(stderr, "USAGE: %s <port>\n", argv[0]); exit(1); } // Check usage & args

    // Get and validate port number as integer not string
    port = atoi(argv[1]);
    if (port < 0 || port > 65535) { fprintf(stderr, "otp_enc_d: ERROR, invalid port %d\n", port); exit(2); }
    if (port < 50000) { printf("otp_enc_d: WARNING, recommended to use a port number above 50000\n"); }
    if (DEBUG) { printf("DEBUG: using port: %d\n", port); } // DEBUG

    // Set up the address struct for this process (the server)
    memset((char *)&server, '\0', sizeof(server)); // Clear out the address struct
    server.sin_family = AF_INET; // Create a network-capable socket
    server.sin_port = htons(port); // Store the port number
    server.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

    // Create and set up the socket
    if ((listeningFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "otp_enc_d: ERROR, opening socket\n"); exit(2);
    }
    if (DEBUG) { printf("DEBUG: listening ocket FD setup: %d\n", listeningFD); } // DEBUG

    // Enable the socket to begin listening
    if (bind(listeningFD, (struct sockaddr *)&server, sizeof(server)) < 0) { // Connect socket to port
        fprintf(stderr, "otp_enc_d: ERROR, on binding\n"); exit(2);
    }
    listen(listeningFD, 5); // Flip the socket on - it can now receive up to 5 connections
    if (DEBUG) { printf("DEBUG: socket binded and now listening for connections\n"); } // DEBUG

    // Enter infinite loop
    while(1) {
        
        // Accept a connection, blocking if one is not available until one connects
        clientSize = sizeof(client); // Get the size of the address for the client that will connect
        if ((connectedFD = accept(listeningFD, (struct sockaddr *)&client, &clientSize)) < 0) { // Accept the connection
            fprintf(stderr, "otp_enc_d: ERROR, on accept\n");
        }
        if (DEBUG) { printf("DEBUG: accepted client on socket FD: %d\n", connectedFD); } // DEBUG

        pid = fork(); // Spawn new child process

        if (pid < 0) { fprintf(stderr, "otp_enc_d: ERROR, fork() failure\n"); } // If the fork failed
        else if (pid == 0) { // Child process

            // Receive authentication from client
            if ((chars = sendrecv(connectedFD, id, ID_LEN, false)) != ID_LEN) {
                fprintf(stderr, "otp_enc_d: ERROR, only %d chars were received from client on port %d\n", chars, port);
            }
            if (DEBUG) { printf("DEBUG: received id from client: %s\n", id); } // DEBUG

            // Validate authorization
            memset(auth, '\0', sizeof(auth));
            if (strcmp(id, "otp_enc") == 0) { strcpy(auth, "PASS"); } 
            else { strcpy(auth, "FAIL"); }
            if (DEBUG) { printf("DEBUG: sending auth back to client: %s\n", auth); } // DEBUG

            // Send authorization result back to client
            if ((chars = sendrecv(connectedFD, auth, AUTH_LEN, true)) != AUTH_LEN) {
                fprintf(stderr, "otp_enc_d: ERROR, only %d chars were sent to client on port %d\n", chars, port);
            }
            
            // If authorization was successful, prepare to receive next messags
            if (strcmp(auth, "PASS") == 0) {
                
                // Receive the plaintext file length from the client
                char textLenBuf[BUF_LEN+1]; // To hold the length of the plaintext file (no more than 9 digit long number)
                if ((chars = sendrecv(connectedFD, textLenBuf, BUF_LEN, false)) != BUF_LEN) {
                    fprintf(stderr, "otp_enc_d: ERROR, only %d chars were received from client on port %d\n", chars, port);
                }
                textLen = atoi(textLenBuf); // Convert to int
                if (DEBUG) { printf("DEBUG: text length received from client: %d\n", textLen); } // DEBUG
        
                // Receive the plaintext file content from the client
                char plaintext[textLen+1]; // +1 for the ending null character
                if ((chars = sendrecv(connectedFD, plaintext, textLen, false)) != textLen) {
                    fprintf(stderr, "otp_enc_d: ERROR, only %d chars were received from client on port %d\n", chars, port);
                }
                if (DEBUG) { printf("DEBUG: plaintext content received from client: %s\n", plaintext); } // DEBUG

                // Receive the key file length from the client
                char keyLenBuf[BUF_LEN+1]; // To hold the length of the key file
                if ((chars = sendrecv(connectedFD, keyLenBuf, BUF_LEN, false)) != BUF_LEN) {
                    fprintf(stderr, "otp_enc_d: ERROR, only %d chars were received from client on port %d\n", chars, port);
                }
                keyLen = atoi(keyLenBuf); // Convert to int
                if (DEBUG) { printf("DEBUG: key length received from client: %d\n", keyLen); } // DEBUG
                
                // Receive the key file content from the client
                char key[keyLen+1];
                if ((chars = sendrecv(connectedFD, key, keyLen, false)) != keyLen) {
                    fprintf(stderr, "otp_enc_d: ERROR, only %d chars were received from client on port %d\n", chars, port);
                }
                if (DEBUG) { printf("DEBUG: key contents received from client: %s\n", key); } // DEBUG

                // Encrypt the plaintext file contents
                char ciphertext[textLen+1];
                encrypt(plaintext, key, ciphertext, textLen);
                if (DEBUG) { printf("DEBUG: sending encrypted ciphertext to client: %s\n", ciphertext); } // DEBUG

                // Send the encrypted ciphertext back to the client
                if ((chars = sendrecv(connectedFD, ciphertext, textLen, true)) != textLen) {
                    fprintf(stderr, "otp_enc_d: ERROR, only %d chars were sent to client on port %d\n", chars, port);
                }
            }

            close(listeningFD); // Close the child's copy of the listening file descriptor
            close(connectedFD); // Close child's copy of new file descriptor

            if (DEBUG) { printf("DEBUG: end of child process %d reached\n", pid); }
            exit(0); // Exit child process
        }
        else { // Parent process

            close(connectedFD); // Close the parent's new file descriptor which is connected to the client
            while (pid > 0) { pid = waitpid(-1, &status, WNOHANG); } // Check if any child processes have completed
            if (DEBUG) { printf("DEBUG: end of parent process %d reached\n", pid); } // DEBUG
        }
    } // End main while loop

    close(listeningFD); // Close the listening socket
    return 0; 
}

/*************************************************************************************************************************
 * Function Definitions 
*************************************************************************************************************************/

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
    int n;         // To hold how many chars get sent with each send()/recv() call

    if (!sendMode) { memset(str, '\0', len+1); } // If receiving, clear the str buffer

    while (total < len) { // Process the entire buffer

        if (sendMode) { n = send(sockFD, str+total, rem, 0); }
        else { n = recv(sockFD, str+total, rem, 0); }
        if (n == -1) { break; }
        total += n;
        rem -= n;
        if (DEBUG) { printf("DEBUG: bytes sent/recv: %d\nbytes total: %d\nbytes rem:%d\n", n, total, rem); } // DEBUG
    }

    if (DEBUG) { printf("DEBUG: total bytes sent/recv: %d out of %d\n", total, len); } // DEBUG
    return total; // If processed successfully, total should equal len
}

/*
 * Encrypts the given plaintext using the given key to produce the ciphertext message
 * Assumes keyLen > textLen and that all arguments are valid with no bad characters (all validation done client side)
 * char* plain: the plaintext to encrypt
 * char* key: the key to use to do the One-Time Pad decryption
 * char* cipher: the string container to hold the encrypted ciphertext
 * int len: the length of the ciphertext and plaintext
*/
void encrypt(char* plain, char* key, char* cipher, int len) {

    int i, cPlain, cKey, cCipher;

    memset(cipher, '\0', len+1);
    for (i = 0; i < len; i++) {

        // Convert spaces
        if (plain[i] == ' ') { plain[i] = '@'; }
        if (key[i] == ' ') { key[i] = '@'; }

        // Get converted characters
        cPlain = (int)plain[i];
        cKey = (int)key[i];

        // Reduce to 0-26 range
        cPlain -= 64;
        cKey -= 64;

        // OTP encryption formula
        cCipher = (cPlain + cKey) % 27;

        // Convert back and append
        cipher[i] = (char)(cCipher + 64);

        // Check for space re-conversion
        if (cipher[i] == '@') { cipher[i] = ' '; }
    }
}
