#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <cassert>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>

SSL_CTX *init(void){
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();      /* load & register cryptos */
  SSL_load_error_strings();          /* load all error messages */
  method = SSLv3_client_method();    /* create client instance */
  ctx = SSL_CTX_new(method);         /* create context */

  return ctx;
}

void load_certificate(const char *CertFile, const char *KeyFile, SSL_CTX *ctx){
  /* set the local certificate from CertFile */
  SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM);

  /* set the private key from KeyFile */
  SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM);

  /* verify private key */
  if( !SSL_CTX_check_private_key(ctx) ){
    fprintf(stderr, "Private key not consistent with corresponding public certificate\n");
    abort();
  }
}

int connect(const int &port, const char *hostname){
  /*--- Standard TCP Client ---*/
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;

  host = gethostbyname(hostname);   /* convert hostname IP address */
  sd = socket(PF_INET, SOCK_STREAM, 0);       /* create TCP socket */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);                 /* set desired port */
  addr.sin_addr.s_addr = *(long *)(host->h_addr);   /* and address */
  connect(sd, (struct sockaddr*)&addr, sizeof(addr));   /* connect */

  return sd;
}

SSL *connect_secure_socket(SSL_CTX *ctx, int server){
  SSL *ssl;
  ssl = SSL_new(ctx);        /* create new SSL connection state */
  SSL_set_fd(ssl, server);   /* attach the socket descriptor */
  SSL_connect(ssl);          /* perform the connection */

  return ssl;
}

void close_socket(SSL *ssl){
  int server;
  server = SSL_get_fd(ssl);   /* get the raw connection */
  SSL_free(ssl);              /* release SSL state */
  close(server);              /* close connection */
}

SSL *client_setup(const int &port, const char *hostname, const char *CertFile, const char *KeyFile){
  SSL_CTX *ctx;
  ctx = init();
  load_certificate(CertFile, KeyFile, ctx);

  int sd;
  SSL *ssl;
  sd = connect(port, hostname);
  ssl = connect_secure_socket(ctx, sd);

  return ssl;
}

void usage(int argc, char *argv[]){
  printf("Inputted:  ");
  for(int i = 0; i < argc; ++i){
    printf("%s ", argv[i]);
  }
  printf("\n");
  printf("Format:\t   ./client hostname(optional) port_no(optional)\n");
  printf("Default hostname: 127.0.0.1\n");
  printf("Default port number: 5678\n");
}

int main(int argc, char *argv[]){

  int portno;
  char hostname[256];
  int argn = 1;
  if(argc == 3){
    strcpy(hostname, argv[argn++]);
    portno = atoi(argv[argn++]);
  }else if(argc == 1){
    strcpy(hostname, "127.0.0.1");
    portno = 5678;
  }else{
    usage(argc, argv);
    exit(0);
  }

  const char *CertificationFile = "cert.pem";
  const char *PrivateKeyFile = "key.pem";

  SSL *ssl;
  char buf[256];
  char reply[256];

  SSL_library_init();

  ssl = client_setup(portno, hostname, CertificationFile, PrivateKeyFile);

  /* now can read/write */
  while(1){
    memset(buf, 0, sizeof(buf));
    memset(reply, 0, sizeof(reply));
    printf("Input a number:");
    scanf("%s", reply);
    SSL_write(ssl, reply, sizeof(reply));   /* send reply */
    SSL_read(ssl, buf, sizeof(buf));        /* get HTTP request */
    /* ... process request */
    if(strcmp(buf, "exit") == 0) break;
    printf("%s\n", buf);
    /* ... */
  }
  printf("Correct\n");

  close_socket(ssl);

  return 0;
}
