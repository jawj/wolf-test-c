
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "certs/cacert-isgrootx1.c"

int ret;
size_t len;
char buff[1600]; // originally 256

WOLFSSL_CTX *ctx = NULL;
WOLFSSL *ssl = NULL;

int (*jsProvideEncryptedFromNetwork)(char *buff, int maxSize);
void (*jsReceiveDecryptedFromLibrary)(char *buff, int size);
int (*jsWriteEncryptedToNetwork)(char *buff, int size);
// + JS expects to call write and recv here as appropriate

void init(
    int (*newJsProvideEncryptedFromNetwork)(char *buff, int maxSize),
    void (*newJsReceiveDecryptedFromLibrary)(char *buff, int size),
    int (*newJsWriteEncryptedToNetwork)(char *buff, int size))
{
  wolfSSL_Init();
  jsProvideEncryptedFromNetwork = newJsProvideEncryptedFromNetwork;
  jsReceiveDecryptedFromLibrary = newJsReceiveDecryptedFromLibrary;
  jsWriteEncryptedToNetwork = newJsWriteEncryptedToNetwork;
}

int my_IORecv(WOLFSSL *ssl, char *buff, int sz, void *ctx)
{
  int recvd = jsProvideEncryptedFromNetwork(buff, sz);

  if (recvd == -1)
  {
    fprintf(stderr, "General error\n");
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  if (recvd == 0)
  {
    puts("Connection closed");
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  }

  printf("%s", "recv:");
  for (int i = 0; i < sz; i++)
    printf(" %02x", (unsigned char)buff[i]);
  puts("");

  printf("received %d bytes from JS\n\n", recvd);
  return recvd;
}

int my_IOSend(WOLFSSL *ssl, char *buff, int sz, void *ctx)
{
  printf("%s", "send:");
  for (int i = 0; i < sz; i++)
    printf(" %02x", (unsigned char)buff[i]);
  puts("");

  int sent = jsWriteEncryptedToNetwork(buff, sz);

  printf("sent %d bytes to JS\n", sz);
  return sent;
}

void cleanup()
{
  if (ssl)
  {
    wolfSSL_free(ssl);
    ssl = NULL;
  }
  if (ctx)
  {
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
  }
  wolfSSL_Cleanup();
}

int handshake(char *tlsHost, char *tlsPort)
{
  ctx = wolfSSL_CTX_new(wolfTLS_client_method());
  if (ctx == NULL)
  {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto exit;
  }

  ret = wolfSSL_CTX_load_verify_buffer(ctx, rootCert, sizeof(rootCert) - 1 /* omit terminal null */, WOLFSSL_FILETYPE_PEM);
  if (ret != WOLFSSL_SUCCESS)
  {
    fprintf(stderr, "ERROR: failed to load cert, please check the buffer.\n");
    goto exit;
  }

  wolfSSL_SetIORecv(ctx, my_IORecv);
  wolfSSL_SetIOSend(ctx, my_IOSend);

  ssl = wolfSSL_new(ctx);
  if (ssl == NULL)
  {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
    ret = -1;
    goto exit;
  }

  ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, tlsHost, strlen(tlsHost));
  if (ret != WOLFSSL_SUCCESS)
  {
    fprintf(stderr, "ERROR: failed to set host for SNI\n");
    goto exit;
  }

  ret = wolfSSL_check_domain_name(ssl, tlsHost);
  if (ret != WOLFSSL_SUCCESS)
  {
    puts("Failed to enable domain name check");
    goto exit;
  };

  ret = wolfSSL_connect(ssl);
  if (ret != WOLFSSL_SUCCESS)
  {
    int err = wolfSSL_get_error(ssl, ret);
    fprintf(stderr, "ERROR: failed to connect to wolfSSL, error %i\n", err);
    goto exit;
  }

  // char getReqBuff[1024];
  // snprintf(getReqBuff, sizeof(getReqBuff), "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", reqPath, tlsHost);
  // len = strlen(getReqBuff);

  // if ((ret = wolfSSL_write(ssl, getReqBuff, len)) != len) {
  //     fprintf(stderr, "ERROR: failed to write\n");
  //     goto exit;
  // }

  // do {
  //     ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1 /* leave space for null-termination */);
  //     if (ret == -1) {
  //         fprintf(stderr, "ERROR: failed to read\n");
  //         goto exit;
  //     }
  //     if (ret > 0) {
  //         buff[ret] = 0;  // null-terminate the string
  //         printf("data: %s\n", buff);
  //     }

  // } while (ret > 0);

  return 0;

exit:
  cleanup();
  return -1;
}

int receiveData()
{ // prompt WolfSSL to read (via JS callback) and decrypt data
  ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1 /* space to null-terminate string */);
  if (ret < 0)
  {
    fprintf(stderr, "ERROR: failed to read\n");
    return ret;
  }
  if (ret == 0)
  {
    fprintf(stderr, "Zero-length read\n");
    return ret;
  }

  buff[ret] = 0; // null-terminate the string for printing
  printf("data: %s\n", buff);

  jsReceiveDecryptedFromLibrary(buff, ret);
  return ret;
}

void writeData(char *buff, int sz)
{ // ask WolfSSL to encrypt an send (via JS callback) data
  ret = wolfSSL_write(ssl, buff, sz);
  if (ret != sz)
  {
    fprintf(stderr, "ERROR: failed to write\n");
  }
}
