#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/timeb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <poll.h>
#include <signal.h>

#define MAX_REQUEST_SIZE 10000000
#define CMD_LEN 275
#define MAX_CONCURRENCY_LIMIT 8

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

// Message type structure
typedef enum {
	IDLE, 		//0
	REGISTER,	//1
	LOGIN,		//2
	LOGOUT,		//3
	SEND,		//4
	SEND2,		//5
	SENDA,		//6
	SENDA2,		//7
	SENDF,		//8
	SENDF2,		//9
	LIST,		//10
	DELAY		//11
} msg_type;

// converting string (from script) to enumerated protocol message
int strToMsg (char *msg) {
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

struct CONN_STAT {
	int msg;		//0 if idle/unknown
	int nRecv;
	int nToRecv;
	int nSent;
	int nToSend;
	int timeout;
	char data[MAX_REQUEST_SIZE];
};

int nConns;
struct pollfd peers[MAX_CONCURRENCY_LIMIT+1];	//sockets to be monitored by poll()
struct CONN_STAT connStat[MAX_CONCURRENCY_LIMIT+1];	//app-layer stats of the sockets

void Error(const char * format, ...) {
	char msg[4096];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "Error: %s\n", msg);
	exit(-1);
}

void Log(const char * format, ...) {
	char msg[2048];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "%s\n", msg);
}

msg_type cmdToMsg (char *str) {
	msg_type msg;

	char *split = strchr(str, ' ');
	if (split != NULL)
		*split = '\0';
	
	// Convert the command string to its corresponding enumerated value
	if ((msg = strToMsg(str)) == -1) {
		Log("ERROR: Unknown message %d", msg);
		return -1;
	}
	
	if (split != NULL)
		*split = ' ';
	
	return msg;
}

int Send_NonBlocking(int sockFD, const BYTE * data, int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {	
	while (pStat->nSent < len) {
		//pStat keeps tracks of how many bytes have been sent, allowing us to "resume" 
		//when a previously non-writable socket becomes writable. 
		int n = send(sockFD, data + pStat->nSent, len - pStat->nSent, 0);
		if (n >= 0) {
			pStat->nSent += n;
		} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) {
			//The socket becomes non-writable. Exit now to prevent blocking. 
			//OS will notify us when we can write
			pPeer->events |= POLLWRNORM; 
			return 0; 
		} else {
			Error("Unexpected send error %d: %s", errno, strerror(errno));
		}
	}
	pPeer->events &= ~POLLWRNORM;
	return 0;
}

int Recv_NonBlocking(int sockFD, BYTE * data, int len, struct CONN_STAT * pStat, struct pollfd * pPeer) { // void * data?
	//pStat keeps tracks of how many bytes have been rcvd, allowing us to "resume" 
	//when a previously non-readable socket becomes readable. 
	while (pStat->nRecv < len) {
		int n = recv(sockFD, data + pStat->nRecv, len - pStat->nRecv, 0);
		if (n > 0) {
			pStat->nRecv += n;
		} else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) { 
			//The socket becomes non-readable. Exit now to prevent blocking. 
			//OS will notify us when we can read
			return 0; 
		} else {
			Error("Unexpected recv error %d: %s.", errno, strerror(errno));
		}
	}
	
	return 0;
}

void SetNonBlockIO(int fd) {
	int val = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, val | O_NONBLOCK) != 0) {
		Error("Cannot set nonblocking I/O.");
	}
}

//void RemoveConnection(int i) {
//	close(peers[i].fd);	
//	if (i < nConns) {	
//		memmove(peers + i, peers + i + 1, (nConns-i) * sizeof(struct pollfd));
//		memmove(connStat + i, connStat + i + 1, (nConns-i) * sizeof(struct CONN_STAT));
//	}
//	nConns--;
//}

int reg(int sock, char *cred) {
	// send the username and password of the new account
	int n = send(sock, cred, CMD_LEN, 0);
	
	if (Recv_NonBlocking(peers[0].fd, connStat[0].data, CMD_LEN, &connStat[0], &peers[0]) < 0 || connStat[0].nRecv == CMD_LEN) {
		connStat[0].nRecv = 0;
		Log("%s", connStat[0].data);
	}
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
	char *line = (char *)malloc(sizeof(char) * CMD_LEN);
	char *command = (char *)malloc(sizeof(char) * CMD_LEN);
	char *buf = (char *)malloc(sizeof(char) * MAX_REQUEST_SIZE);
	int n;
	
	// command line arguments must follow form detailed in project outline
	if (argc < 4) {
		Error("Incorrect number of arguments. Proper usage: './client [Server IP Address] [Server Port] [Input Script]'");
	}
	memset(line, 0, CMD_LEN);
	memset(command, 0, CMD_LEN);
	
	// grab port from command line
	int port = atoi(argv[2]);

	//Set the destination IP address and port number
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) port);
	inet_pton(AF_INET, argv[1], &serverAddr.sin_addr);
	
	// Create the socket that will receive messages
	int msgSock = socket(AF_INET, SOCK_STREAM, 0);
	// SET NONBLOCK
	if (connect(msgSock, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) > 0) {	
		
	}

	nConns = 0;	
	memset(peers, 0, sizeof(peers));	
	peers[0].fd = msgSock;
	peers[0].events = POLLRDNORM | POLLWRNORM;	
	memset(connStat, 0, sizeof(connStat));
	connStat[0].timeout = -1;
	
	// Open the input script
	FILE * input;
	size_t len = 0;
	if((input = fopen(argv[3], "r")) == NULL) {
		printf("Unable to open file '%s'.\n", argv[3]);
		return -1;
	}
	
	while(1) {
		// This poll effectively implements a delay
		int r = poll(peers, nConns + 1, connStat[0].timeout);
		if (r == 0) {
			connStat[0].timeout = -1;
			peers[0].events |= POLLWRNORM;
		}
		
		//if (peers[0].revents & POLLRDNORM) {
		//	recv(peers[0].fd, (BYTE *)&connStat[0].nToRecv, sizeof(int), 0);
		//	int n = recv(peers[0].fd, connStat[0].data, connStat[0].nToRecv, 0);
		//	Log("%s", n, connStat[0].data);
		//	continue;
		//}
		
		if (getline(&line, &len, input) == -1) {
			break;
		}	
	
		char *split = strchr(line, ' ');
		if (split != NULL) {
			*split = '\0';
		}
		
		printf("%s %s", line, split+1);
		
		// Grab the message type and command from the 
		int msg = strToMsg(line);
		sprintf(command, "%s", split+1);
		
		switch (msg) {
			case REGISTER:
				reg(peers[0].fd, command);
				break;
			case LOGIN:
			
			case LOGOUT:
			
			case SEND:
			
			case SEND2:
			
			case SENDA:
			
			case SENDA2:
			
			case SENDF:
			
			case SENDF2:
			
			case LIST:
			
			case DELAY: {
				connStat[0].timeout = atoi(command);
				peers[0].events &= ~POLLWRNORM;
				continue;
			}
		}
		
	}
	
	// Close the input file after end of file
	if (fclose(input) < 0) {
		Error("Attempt to close input script failed.");
	}
	
	// After execution, allocated memory can be freed
	free(command);
	free(line);

	//Close socket
	close(msgSock);
	return 0;
}

