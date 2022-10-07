
#include <emscripten.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "certs/cacert-isgrootx1.c"
// #include "certs/cacerts.c"

int ret;
size_t len;
char buff[8192];  // originally 256

WOLFSSL_CTX *ctx = NULL;
WOLFSSL *ssl = NULL;
int inited = 0;

EM_ASYNC_JS(int, jsProvideEncryptedFromNetwork, (char *buff, int sz), {
  const bytesRead = await Module.provideEncryptedFromNetwork(buff, sz);
  return bytesRead;
});

EM_JS(int, jsWriteEncryptedToNetwork, (char *buff, int sz), {
  const bytesWritten = Module.writeEncryptedToNetwork(buff, sz);
  return bytesWritten;
});

EM_JS(int, jsReceiveDecryptedFromLibrary, (char *buff, int sz), {
  void 0;  // for code formatting!
  Module.jsReceiveDecryptedFromLibrary(buff, sz);
});

int my_IORecv(WOLFSSL *ssl, char *buff, int sz, void *ctx) {
  int recvd = jsProvideEncryptedFromNetwork(buff, sz);

  if (recvd == -1) {
    fprintf(stderr, "General error\n");
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  if (recvd == 0) {
    puts("0 bytes received, connection closed");
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  }

  printf("%s", "recv:");
  for (int i = 0; i < sz; i++) printf(" %02x", (unsigned char)buff[i]);
  puts("");

  printf("received %d bytes from JS\n\n", recvd);
  return recvd;
}

int my_IOSend(WOLFSSL *ssl, char *buff, int sz, void *ctx) {
  printf("%s", "send:");
  for (int i = 0; i < sz; i++) printf(" %02x", (unsigned char)buff[i]);
  puts("");

  int sent = jsWriteEncryptedToNetwork(buff, sz);

  printf("sent %d bytes to JS\n", sz);
  return sent;
}

void cleanup() {
  if (ssl) {
    wolfSSL_free(ssl);
    ssl = NULL;
  }
  if (ctx) {
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
  }
  wolfSSL_Cleanup();
}

int handshake(char *tlsHost) {
  if (!inited) {
    puts("handshake: init");
    wolfSSL_Init();
    inited = 1;
  }

  puts("handshake: create context");
  ctx = wolfSSL_CTX_new(wolfTLS_client_method());
  if (ctx == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto exit;
  }

  puts("handshake: load certs");
  ret = wolfSSL_CTX_load_verify_buffer(
      ctx, rootCert, sizeof(rootCert) - 1 /* omit terminal null */,
      WOLFSSL_FILETYPE_PEM);
  if (ret != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load cert, please check the buffer.\n");
    goto exit;
  }

  // printf("handshake: certs consist of %li bytes\n", strlen(rootCert));

  puts("handshake: set IO handlers");
  wolfSSL_SetIORecv(ctx, my_IORecv);
  wolfSSL_SetIOSend(ctx, my_IOSend);

  puts("handshake: create SSL obj");
  ssl = wolfSSL_new(ctx);
  if (ssl == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
    ret = -1;
    goto exit;
  }

  puts("handshake: set SNI");
  ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, tlsHost, strlen(tlsHost));
  if (ret != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to set host for SNI\n");
    goto exit;
  }

  puts("handshake: set domain check");
  ret = wolfSSL_check_domain_name(ssl, tlsHost);
  if (ret != WOLFSSL_SUCCESS) {
    puts("Failed to enable domain name check");
    goto exit;
  };

  puts("handshake: connect");
  ret = wolfSSL_connect(ssl);
  if (ret != WOLFSSL_SUCCESS) {
    int err = wolfSSL_get_error(ssl, ret);
    fprintf(stderr, "ERROR: failed to connect to wolfSSL, error %i\n", err);
    goto exit;
  }

  // char getReqBuff[1024];
  // snprintf(getReqBuff, sizeof(getReqBuff), "GET %s HTTP/1.0\r\nHost:
  // %s\r\n\r\n", reqPath, tlsHost); len = strlen(getReqBuff);

  // if ((ret = wolfSSL_write(ssl, getReqBuff, len)) != len) {
  //     fprintf(stderr, "ERROR: failed to write\n");
  //     goto exit;
  // }

  // do {
  //     ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1 /* leave space for
  //     null-termination */); if (ret == -1) {
  //         fprintf(stderr, "ERROR: failed to read\n");
  //         goto exit;
  //     }
  //     if (ret > 0) {
  //         buff[ret] = 0;  // null-terminate the string
  //         printf("data: %s\n", buff);
  //     }

  // } while (ret > 0);

  puts("handshake: done");
  return 0;

exit:
  cleanup();
  return -1;
}

int readData(char *buff, int sz) {
  ret = wolfSSL_read(ssl, buff, sz);
  if (ret < 0) {
    fprintf(stderr, "ERROR: failed to read\n");
    return ret;
  }
  if (ret == 0) {
    fprintf(stderr, "Zero-length read\n");
    return ret;
  }

  return ret;
}

int writeData(char *buff, int sz) {
  ret = wolfSSL_write(ssl, buff, sz);
  if (ret != sz) {
    fprintf(stderr, "ERROR: failed to write\n");
  }
  return ret;
}
