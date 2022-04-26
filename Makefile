build: server.c client.c
	gcc server.c -o server
	gcc client.c -o client

server: server.c
	gcc server.c -o server
	
client: client.c
	gcc client.c -o client
	
clean: client
	rm server client registered_accounts.txt
