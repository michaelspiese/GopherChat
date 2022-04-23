build: server.c client.c
	gcc server.c -o server
	gcc client.c -o client

server: server.c
	gcc server.c -o server
	
client: client.c
	gcc client.c -o client
	
run: server
	./server 6001

reset:
	./server reset
	
testL: client
	./client 127.0.0.1 6001 test.txt
	
testL2: client
	./client 127.0.0.1 6001 test2.txt
	
testA: client
	./client 3.94.168.98 6001 test.txt
	
testA2: client
	./client 3.94.168.98 6001 test2.txt
	
clean: client
	rm server client registered_accounts.txt
