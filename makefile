GCC 	= 	g++ -std=c++14
OPT 	=	-O2
WARN 	=	-Wall -Wextra -pedantic
OPENSSL =	-lssl -lcrypto
CLIENT	=	p4_elee36_client
SERVER	=	p4_elee36_server

all: client server

client: $(CLIENT).o
	$(GCC) $(OPT) $(CLIENT).o -o client $(OPENSSL)

server: $(SERVER).o
	$(GCC) $(OPT) $(SERVER).o -o server $(OPENSSL)

warnings: cli_wrning serv_wrning

cli_wrning: $(CLIENT).o
	$(GCC) $(WARN) $(CLIENT).o -o client $(OPENSSL)

serv_wrning: $(SERVER).o
	$(GCC) $(WARN) $(SERVER).o -o server $(OPENSSL)

client.o: $(CLIENT).cpp
	$(GCC) $(CLIENT).cpp -c client.o

server.o: $(SERVER).cpp
	$(GCC) $(SERVER).cpp -c server.o

clear:
	rm -f *~ *.o client server