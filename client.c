#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024

//AES key and IV (must match the server-side)
unsigned char key[16] = "threadslabAESkey";   //128-bit key
unsigned char iv[16]  = "initialvector123";   //16-byte IV

//Encrypt function
int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};

    //Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    //Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    //Define the server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; //localhost

    //Connect to the server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    //Create SSL context and object
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    //Performing the TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        //The username input
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Server: %s\n", buffer);
        char username[BUFFER_SIZE];
        printf("Enter username: ");
        scanf("%s", username);
        SSL_write(ssl, username, strlen(username));

        //The password input
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Server: %s\n", buffer);
        char password[BUFFER_SIZE];
        printf("Enter password: ");
        scanf("%s", password);
        SSL_write(ssl, password, strlen(password));

        //Read authentication result
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Server: %s\n", buffer);

        //If access denied, exit immediately
        if (strcmp(buffer, "Access denied") == 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return 0;
        }

        //Otherwise continue with the secure communication using AES
        char msg[BUFFER_SIZE];
        printf("Enter message to send: ");
        scanf(" %[^\n]", msg); //allow spaces

        unsigned char encrypted[BUFFER_SIZE];
        int ciphertext_len = encrypt((unsigned char*)msg, strlen(msg), encrypted);

        //Send encrypted message
        SSL_write(ssl, encrypted, ciphertext_len);

        //Receive the server response
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Server: %s\n", buffer);
    }


    //Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    return 0;
}
