build: server.c client.c
	gcc server.c -o server
	gcc client.c -o client

server: server.c
	gcc server.c -o server
	
client: client.c
	gcc client.c -o client
	
run:
	./server 6001

reset:
	./server reset
	
testL:
	./client 127.0.0.1 6001 test.txt
	
testA:
	./client 3.94.168.98 6001 test.txt
	
clean:
	rm server client registered_accounts.txt
