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
unsigned char key[16] = "threadslabAESkey";     //128-bit key
unsigned char iv[16]  = "initialvector123";     //16-byte IV

// Encrypt function (client to server)
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
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define the server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    //Wrap the socket with SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    //Performing the TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        printf("TLS handshake successful. Using %s\n", SSL_get_cipher(ssl));
    }

    char buffer[BUFFER_SIZE];
    int bytes;

    //The username input
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = '\0';
    printf("Server: %s\n", buffer);

    printf("Enter username: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';
    SSL_write(ssl, buffer, strlen(buffer));

    //The password input
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = '\0';
    printf("Server: %s\n", buffer);

    printf("Enter password: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';
    SSL_write(ssl, buffer, strlen(buffer));

    //The Access authentication result
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = '\0';
    printf("Server: %s\n", buffer);

    //If access denied, exit immediately, Otherwise continue with the secure communication using AES
    if (strcmp(buffer, "Access denied") == 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 0;
    }

    //input the command or message to be sent to the server
    while (1) {
        printf("Enter message to send: ");
        fgets(buffer, sizeof(buffer), stdin);
        buffer[strcspn(buffer, "\n")] = '\0';

        if (strcmp(buffer, "exit") == 0) break;

        //Encrypt message before sending
        unsigned char ciphertext[BUFFER_SIZE];
        int ciphertext_len = encrypt((unsigned char*)buffer, strlen(buffer), ciphertext);

        SSL_write(ssl, ciphertext, ciphertext_len);

        //Receive server's response (plain text)
        unsigned char reply[BUFFER_SIZE];
        int reply_bytes = SSL_read(ssl, reply, sizeof(reply));
        if (reply_bytes > 0) {
            reply[reply_bytes] = '\0';
            printf("Server reply: %s\n", reply);
        }
    }

    //Cleanup to prevent memory leaks
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
