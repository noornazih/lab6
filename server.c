#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024

//AES key and IV (must match client)
unsigned char key[16] = "threadslabAESkey";   //128-bit key
unsigned char iv[16]  = "initialvector123";   //16-byte IV

//Setting up the extra AES key layer and encrypting
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

//Decrypt function 
int decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

//Permission check function on what command permitted or denied
int check_permission(const char *role, const char *cmd) {
    if (strcmp(role, "Entry") == 0) {
        if (strstr(cmd, "rm") != NULL ||
            strncmp(cmd, "nano", 4) == 0 ||
            strncmp(cmd, "vi", 2) == 0 ||
            strncmp(cmd, "vim", 3) == 0 ||
            strncmp(cmd, "touch", 5) == 0 ||
            strncmp(cmd, "cp", 2) == 0 ||
            strncmp(cmd, "mv", 2) == 0) {
            return 0;
        }
        return 1;
    }
    else if (strcmp(role, "Medium") == 0) {
        if (strstr(cmd, "rm") != NULL ||
            strncmp(cmd, "unlink", 6) == 0 ||
            strncmp(cmd, "rmdir", 5) == 0 ||
            strncmp(cmd, "shred", 5) == 0 ||
            strncmp(cmd, "wipe", 4) == 0) {
            return 0;
        }
        return 1;
    }
    else if (strcmp(role, "Top") == 0) {
        return 1;
    }
    return 0;
}

//The Thread function to handle each client
void *the_clients(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE] = {0};

    //The Username Input
    SSL_write(ssl, "Enter username:", strlen("Enter username:"));
    SSL_read(ssl, buffer, sizeof(buffer));
    char username[BUFFER_SIZE];
    strcpy(username, buffer);

    //The Password Input
    SSL_write(ssl, "Enter password:", strlen("Enter password:"));
    SSL_read(ssl, buffer, sizeof(buffer));
    char password[BUFFER_SIZE];
    strcpy(password, buffer);

    //Check for credentials againt users.txt
    FILE *fp = fopen("users.txt", "r");
    int authenticated = 0;
    char user_role[BUFFER_SIZE] = {0};
    if (fp != NULL) {
        char file_user[BUFFER_SIZE], file_pass[BUFFER_SIZE], file_role[BUFFER_SIZE];
        while (fscanf(fp, "%s %s %s", file_user, file_pass, file_role) != EOF) {
            if (strcmp(username, file_user) == 0 && strcmp(password, file_pass) == 0) {
                authenticated = 1;
                strcpy(user_role, file_role);
                break;
            }
        }
        fclose(fp);
    }

    //Response based on authentication status
    if (!authenticated) {
        SSL_write(ssl, "Access denied", strlen("Access denied"));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    } else {
        SSL_write(ssl, "Access granted", strlen("Access granted"));
    }

    //Secure communication between server-client
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_len = decrypt((unsigned char*)buffer, bytes, decrypted);
        decrypted[decrypted_len] = '\0';

        printf("Client (decrypted): %s\n", decrypted);
        //permission check
        if (check_permission(user_role, (char*)decrypted)) {
            system((char*)decrypted);
            SSL_write(ssl, "Command executed", strlen("Command executed"));
        } else {
            SSL_write(ssl, "Permission Denied", strlen("Permission Denied"));
        }
    }
    //The Cleanup to prevent leakage
    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    //Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    //Create the socket to enable endpoint communication between the two programs
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    //Define the server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    //Bind the socket (link the ip and port)
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    //Listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    //Create SSL context and load self-signed certificate/key
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!SSL_CTX_use_certificate_file(ctx, "server.cert", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //Accept multiple client connections using while loop for unlimited clients
    while(1){
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        //Wrap accepted socket with SSL
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        //Performing TLS handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(new_socket);
            continue;
        } else {
            printf("TLS handshake successful. Using %s\n", SSL_get_cipher(ssl));
        }

        //Spawn a new thread for each client
        pthread_t thread;
        pthread_create(&thread, NULL, the_clients, ssl);
        pthread_detach(thread);
    }

    //The Cleanup to prevent leakage
    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}