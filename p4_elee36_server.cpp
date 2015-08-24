#include "openssl/ssl.h"
#include "openssl/err.h"

#include <iostream>
#include <cassert>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

SSL_CTX *init(void){
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();      /* load & register cryptos */
  SSL_load_error_strings();          /* load all error messages */
  method = SSLv3_server_method();    /* create server instance */
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

int connect(const int &port){
  /*--- Standard TCP server setup and connection --*/
  int sd, client_sd;
  struct sockaddr_in addr;
  sd = socket(PF_INET, SOCK_STREAM, 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);       /*select port */
  addr.sin_addr.s_addr = INADDR_ANY; /* any available addr*/
  bind(sd, (struct sockaddr *)&addr, sizeof(addr)); /* bind it */
  listen(sd, 10);                    /* make into listening socket */
  client_sd = accept(sd, 0, 0);      /* wait and accept connections */

  return client_sd;
}

SSL *open_secure_socket(SSL_CTX *ctx, const int &client){
  SSL *ssl;
  ssl = SSL_new(ctx);        /* get new SSL state with context */
  SSL_set_fd(ssl, client);   /* set connection to SSL state */
  SSL_accept(ssl);           /* start the handshaking */

  return ssl;
}

void close_socket(SSL *ssl){
  int client;
  client = SSL_get_fd(ssl);   /* get the raw connection */
  SSL_free(ssl);              /* release SSL state */
  close(client);              /* close connection */
}

SSL *server_setup(const int &port, const char *CertFile, const char *KeyFile){
  SSL_CTX *ctx;
  ctx = init();
  load_certificate(CertFile, KeyFile, ctx);

  int sd;
  SSL *ssl;
  sd = connect(port);
  ssl = open_secure_socket(ctx, sd);

  return ssl;
}

void usage(int argc, char *argv[]){
  printf("Inputted:  ");
  for(int i = 0; i < argc; ++i){
    printf("%s ", argv[i]);
  }
  printf("\n");
  printf("Format:\t   ./server certification.pem private_key.pem port_no(optional)\n");
  printf("Default port number: 5678\n");
}

int main(int argc, char *argv[]){

  int portno;
  int argn = 1;

  char *CertificationFile = argv[argn++];
  char *PrivateKeyFile = argv[argn++];

  if(argc == 4){
    portno = atoi(argv[argn]);
  }else if(argc == 3){
    portno = 5678;
  }else{
    usage(argc, argv);
    exit(0);
  }


  SSL *ssl;
  char buf[256];
  char reply[256];
  int correct = 100;

  SSL_library_init();

  ssl = server_setup(portno, CertificationFile, PrivateKeyFile);

  /* now can read/write */
  printf("Correct Number: %d\n", correct);
  while(1){
    memset(buf, 0, sizeof(buf));
    memset(reply, 0, sizeof(reply));
    SSL_read(ssl, buf, sizeof(buf));        /* get HTTP request */
    /* ... process request */
    printf("number inputted: %s\n", buf);
    if(correct == atoi(buf)) break;
    strcpy(reply, "incorrect");
    SSL_write(ssl, reply, strlen(reply));   /* send reply */
    /* ... */
  }
  printf("Correct Input\n");
  SSL_write(ssl, "exit", strlen("exit"));   /* send reply */
  close_socket(ssl);
  
  return 0;
}
