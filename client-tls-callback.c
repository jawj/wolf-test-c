/* The file is based on: client-tls-callback.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* 

(1) on Mac with homebrew, compile wolfssl like so:

# download from GitHub releases + untar
cd wolfssl-5.5.1-stable
brew install brew install autoconf automake libtool
./autogen
./configure \
  --disable-filesystem --disable-examples --disable-oldtls \
  --enable-sni --enable-tls13 \
  --enable-altcertchains  # alt cert chains are required for Let's Encrypt certs: https://github.com/wolfSSL/wolfssl/issues/4443
make
make install  # to /usr/local/include

(2) compile and test like so:

make client-tls-callback
./client-tls-callback neon.tech 443
./client-tls-callback expired.badssl.com 443  # see badssl.com for other testing domains

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "cacert.c"

int my_IORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int sockfd = *(int*)ctx;
    int recvd;

    /* Receive message from socket */
    if ((recvd = recv(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO RECEIVE ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            if (!wolfSSL_dtls(ssl) || wolfSSL_get_using_nonblock(ssl)) {
                fprintf(stderr, "would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                fprintf(stderr, "socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case ECONNREFUSED:
            fprintf(stderr, "connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            fprintf(stderr, "connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        puts("Connection closed");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    printf("%s", "recv:");
    for (int i = 0; i < sz; i ++) printf(" %02x", (unsigned char)buff[i]);
    puts("");

    /* successful receive */
    printf("received %d bytes from %i\n\n", sz, sockfd);
    return recvd;
}

int my_IOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to write to.
     * This can be changed by calling wolfSSL_SetIOWriteCtx(). */
    int sockfd = *(int*)ctx;
    int sent;

    printf("%s", "send:");
    for (int i = 0; i < sz; i ++) printf(" %02x", (unsigned char)buff[i]);
    puts("");

    /* Receive message from socket */
    if ((sent = send(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO SEND ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            fprintf(stderr, "would block\n");
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case EPIPE:
            fprintf(stderr, "socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        puts("Connection closed");
        return 0;
    }

    /* successful send */
    printf("sent %d bytes to %i\n\n", sz, sockfd);
    return sent;
}

int main(int argc, char** argv)
{
    int                ret; 
    int                sockfd = SOCKET_INVALID;
    struct sockaddr_in servAddr;
    char               buff[256];
    size_t             len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    /* Check for proper calling convention */
    if (argc != 3) {
        printf("usage: %s <IPv4 address> <port>\n", argv[0]);
        return 0;
    }

    char *tlsHost = argv[1];
    char *tlsPort = argv[2];

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1; 
        goto exit;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLS_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto exit;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, rootCert, sizeof(rootCert) - 1 /* omit terminal null */, WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load cert, please check the buffer.\n");
        goto exit;
    }

    /* Register callbacks */
    wolfSSL_SetIORecv(ctx, my_IORecv);
    wolfSSL_SetIOSend(ctx, my_IOSend);

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* NEW: look up name */
    struct hostent *hostnm = gethostbyname(tlsHost);
    if (hostnm == NULL) {
       puts("ERROR: gethostbyname() failed");
       goto exit;
    }

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;  /* using IPv4 */
    servAddr.sin_port = htons(atoi(tlsPort));
    servAddr.sin_addr.s_addr = *((unsigned long *)hostnm->h_addr);

    /* Open TCP connection to the server */
    if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        ret = -1; 
        goto exit;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1; 
        goto exit;
    }

    /* NEW: enable SNI */
    if ((ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, tlsHost, strlen(tlsHost))) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set host for SNI\n");
        goto exit;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    /* Turn on domain name check */
    if ((ret = wolfSSL_check_domain_name(ssl, tlsHost)) != WOLFSSL_SUCCESS) {
        puts("Failed to enable domain name check");
        goto exit;
    };

    /* TLS handshake with server */
    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        fprintf(stderr, "ERROR: failed to connect to wolfSSL, error %i\n", err);
        goto exit;
    }

    char getReqBuff[1024];
    snprintf(getReqBuff, sizeof(getReqBuff), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", tlsHost);
    len = strlen(getReqBuff);

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, getReqBuff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write\n");
        goto exit;
    }

    do {
        ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1 /* leave space for null-termination */);
        if (ret == -1) {
            fprintf(stderr, "ERROR: failed to read\n");
            goto exit;
        }
        if (ret > 0) {
            buff[ret] = 0;  // null-terminate the string
            printf("data: %s\n", buff);
        }

    } while (ret > 0);

    ret = 0;

exit:
    /* Cleanup and return */
    if (ssl)
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
    if (sockfd != SOCKET_INVALID)
        close(sockfd);           /* Close the connection to the server   */
    if (ctx)
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();          /* Cleanup the wolfSSL environment          */

    return ret;               /* Return reporting a success               */
}
