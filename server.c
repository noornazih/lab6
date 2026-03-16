#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept a client connection
    new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL context and load certificate/key
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!SSL_CTX_use_certificate_file(ctx, "server.cert", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {   // load server certificate and the private key
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Wrap accepted socket with SSL
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);

    // Perform TLS handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("TLS handshake successful. Using %s\n", SSL_get_cipher(ssl));

        // Secure communication
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Client: %s\n", buffer);

        SSL_write(ssl, "Hello secure client!", strlen("Hello secure client!"));
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(new_socket);
    close(server_fd);

    return 0;
}
