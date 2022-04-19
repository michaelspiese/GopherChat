#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>

#define MAX_REQUEST_SIZE 10000000
#define MAX_DATA_FRAME 275

// protocol messages
typedef enum {
	IDLE,
	REGISTER,
	LOGIN,
	LOGOUT,
	SEND,
	SEND2,
	SENDA,
	SENDA2,
	SENDF,
	SENDF2,
	LIST,
	DELAY
} msg_type;

// converting string (from script) to enumerated protocol message
msg_type strToMsg (char *msg) {
	if (!strcmp(msg, "REGISTER"))
		return REGISTER;
	else if (!strcmp(msg, "LOGIN"))
		return LOGIN;
	else if (!strcmp(msg, "LOGOUT"))
		return LOGOUT;
	else if (!strcmp(msg, "SEND"))
		return SEND;
	else if (!strcmp(msg, "SEND2"))
		return SEND2;
	else if (!strcmp(msg, "SENDA"))
		return SENDA;
	else if (!strcmp(msg, "SENDA2"))
		return SENDA2;
	else if (!strcmp(msg, "SENDF"))
		return SENDF;
	else if (!strcmp(msg, "SENDF2"))
		return SENDF2;
	else if (!strcmp(msg, "LIST"))
		return LIST;
	else if (!strcmp(msg, "DELAY"))
		return DELAY;
	else
		return -1;
}

int reg(int sock, char *buf) {
	int returnMsg;

	// send the username and password of the new account
	int n = send(sock, buf, 275, 0);
	
	// receive registration status back from server
	n = recv(sock, &returnMsg, sizeof(int), 0);
	
	return returnMsg;
}

/* !! THIS FUNCTION IS THE EXACT SAME AS THE REGISTER FUNCTION !! */
int login(int sock, char *buf) {
	int returnMsg;
	
	// send the login credentials
	int n = send(sock, buf, 275, 0);
	
	// receive registration status back from server
	n = recv(sock, &returnMsg, sizeof(int), 0);
	
	return returnMsg;
} 

int logout(int sock) {
	int returnMsg;
		
	// receive registration status back from server
	int n = recv(sock, &returnMsg, sizeof(int), 0);
	
	return returnMsg;
}

int main(int argc, char *argv[]) {
	char *line = (char *)malloc(sizeof(char) * MAX_DATA_FRAME);
	char *buf = (char *)malloc(sizeof(char) * MAX_REQUEST_SIZE);
	FILE * filename;
	size_t len = 0;
	int port;
	int n;
	
	// command line arguments must follow form detailed in project outline
	if (argc < 4)
		return -1;
		
	memset(line, 0, MAX_DATA_FRAME);
	
	// grab port
	port = atoi(argv[2]);

	//Set the destination IP address and port number
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) port);
	inet_pton(AF_INET, argv[1], &serverAddr.sin_addr);
	
	if((filename = fopen(argv[3], "r")) == NULL) {
		printf("Unable to open file '%s'.\n", argv[3]);
		return -1;
	}
		
	//Create the socket, connect to the server
	int sock = socket(AF_INET, SOCK_STREAM, 0);	
	connect(sock, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	
	while (getline(&line, &len, filename) != -1) {
		memset(buf, 0, MAX_REQUEST_SIZE);
		
		char * const split = strchr(line, ' ');
		if (split != NULL) {
			*split = '\0';
		}
		else {
			printf("invalid\n");
			continue;
		}	
		
		msg_type msg = strToMsg(line);
		if (msg == -1) {
			printf("ERROR: Unknown message\n");
			close(sock);
			return -1;
		}
		
		strcpy(buf, split+1);
		printf("%d %s", msg, buf);
		
		switch(msg) {
			case REGISTER:
				// make sure that the number of arguments is correct, otherwise return
				//if (argc != 4) {
				//	printf("Incorrect number of arguments. Got %d, expected 4.\n", argc);
				//	//return -1;
				//}
				
				// if command is of valid form, send message type to server
				n = send(sock, &msg, sizeof(msg_type), 0);
			
				// use register protocol to send data to server
				if ((n = reg(sock, buf)) == REGISTER) {
					printf("User registered successfully.\n");
				}
				else if (n == -1) {
					printf("User already exists. Please choose new username.\n");
				}
				else {
					printf("Username/password invalid size (4-8 characters). Please choose new credentials.\n");
				}
				break;
			case LOGIN:
				// make sure that the number of arguments is correct, otherwise return
				//if (argc != 4) {
				//	printf("Incorrect number of arguments. Got %d, expected 4.\n");
				//	//return -1;
				//}
				
				// if command is of valid form, send message type to server
				n = send(sock, &msg, sizeof(msg_type), 0);
				
				if ((n = login(sock, buf)) == LOGIN) {
					printf("Successfully logged in user '%s'.\n", argv[2]);
				}
				else {
					printf("Unable to log in. Please check credentials and retry.\n");
				}
				break;
			case LOGOUT:
				// make sure that the number of arguments is correct, otherwise return
				//if (argc != 2) {
				//	printf("Incorrect number of arguments. Got %d, expected 2.\n", argc);
				//	//return -1;
				//}	
				
				// if command is of valid form, send message type to server
				n = send(sock, &msg, sizeof(msg_type), 0);
							
				if ((n = logout(sock)) == LOGOUT) {
					printf("Successfully logged out.\n");
				}
				else {
					printf("Cannot log out, you are not logged in.\n");
				}
				break;
			case DELAY:
				printf("delay\n");
		}
	}
	
	free(buf);
	free(line);

	//Close socket
	close(sock);
	return 0;
}

