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
#define CMD_LEN 300
#define MAX_CONCURRENCY_LIMIT 8

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

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
	else if (!strcmp(msg, "LOGOUT\n"))
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
	else if (!strcmp(msg, "LIST\n"))
		return LIST;
	else if (!strcmp(msg, "DELAY"))
		return DELAY;
	else
		return -1;
}

struct CONN_STAT {
	int msg;		//0 if idle/unknown
	int nRecv;
	int nSent;
	int nStatSent;
	int filesize;
	char *file;
	char filename[33];
	char recipient[9];
	char dataSend[CMD_LEN];
	char data[CMD_LEN];
};

int eof;
int connected;
int timeout;
int nConns;
struct pollfd peers[MAX_CONCURRENCY_LIMIT+1];	//sockets to be monitored by poll()
struct CONN_STAT connStat[MAX_CONCURRENCY_LIMIT+1];	//app-layer stats of the sockets
struct sockaddr_in serverAddr;

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
			//Log("Connection closed.");
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
			//Log("Connection closed.");
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

void RemoveConnection(int i) {
	//Log("Connection %d closed.", i);
	close(peers[i].fd);	
	if (i < nConns) {	
		memmove(peers + i, peers + i + 1, (nConns-i) * sizeof(struct pollfd));
		memmove(connStat + i, connStat + i + 1, (nConns-i) * sizeof(struct CONN_STAT));
	}
	nConns--;
}

void createDataSocket(int type, char *cmd) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	SetNonBlockIO(fd);
	connect(fd, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	if (fd != -1) {
		++nConns;
		peers[nConns].fd = fd;
		peers[nConns].events = POLLWRNORM | POLLRDNORM;
		peers[nConns].revents = 0;
		memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
		if (type == SENDF) {
			char* parse = strtok(cmd, " ");
			parse = strtok(NULL, "");
			sprintf(connStat[nConns].filename, "%s", parse);
			int last = strlen(connStat[nConns].filename);
			connStat[nConns].filename[last-1] = '\0';
			
			// Attempt to open the file
			FILE * file;
			if ((file = fopen(connStat[nConns].filename, "r")) == NULL) {
				Log("ERROR: file does not exist");
				RemoveConnection(nConns);
				return;
			}
			
			// Find the size of the file
			fseek(file, 0, SEEK_END);
			connStat[nConns].filesize = ftell(file);
			fseek(file, 0, SEEK_SET);
			
			// Read the entire file into a buffer of the same size
			connStat[nConns].file = (char *)malloc(sizeof(char) * connStat[nConns].filesize);
			memset(connStat[nConns].file, 0, connStat[nConns].filesize);
			fread(connStat[nConns].file, sizeof(char), connStat[nConns].filesize, file);
			
			// Write a command consisting of the filesize to transmit and the name of the file
			sprintf(connStat[nConns].dataSend, "RECVF %d %s", connStat[nConns].filesize, connStat[nConns].filename);
		}
	}
}

int main(int argc, char *argv[]) {
	char *line = (char *)malloc(sizeof(char) * CMD_LEN);
	int n;
	
	// command line arguments must follow form detailed in project outline
	if (argc < 4) {
		Error("Incorrect number of arguments. Proper usage: './client [Server IP Address] [Server Port] [Input Script]'");
	}
	memset(line, 0, CMD_LEN);
	
	// grab port from command line
	int port = atoi(argv[2]);

	//Set the destination IP address and port number
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) port);
	inet_pton(AF_INET, argv[1], &serverAddr.sin_addr);
	
	// Create the non-blocking socket that will listen to send/receive messages
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	SetNonBlockIO(sock);
	connect(sock, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	if (errno != EINPROGRESS) {	
		Error("Client failed to connect. %s", strerror(errno));
	}

	eof = 0;
	nConns = 0;	
	memset(peers, 0, sizeof(peers));	
	peers[0].fd = sock;
	peers[0].events = POLLRDNORM | POLLWRNORM;	
	memset(connStat, 0, sizeof(connStat));
	timeout = -1;
	
	// Open the input script
	FILE * input;
	size_t len = 0;
	if((input = fopen(argv[3], "r")) == NULL) {
		printf("Unable to open file '%s'.\n", argv[3]);
		return -1;
	}
	
	if(getline(&line, &len, input) == -1) {
		Log("initial getline failed");
		return -1;
	}
	sprintf(connStat[0].dataSend, "%s", line);
	connStat[0].msg = cmdToMsg(connStat[0].dataSend);
	
	while(1) {
		int r = poll(peers, nConns + 1, timeout);	
		if (r == 0) {
			peers[0].events |= POLLWRNORM;		
			
			memset(connStat[0].dataSend, 0, CMD_LEN);
			if(getline(&line, &len, input) == -1) {
				Log("End of script reached, disconnecting from server...");
				break;
			}
			sprintf(connStat[0].dataSend, "%s", line);
			connStat[0].msg = cmdToMsg(connStat[0].dataSend);
			
			if (connStat[0].msg == SENDF || connStat[0].msg == SENDF2) {
				createDataSocket(connStat[0].msg, connStat[0].dataSend);
			}
			
			if (connStat[0].msg == DELAY) {
				char* parse = strtok(line, " ");
				parse = strtok(NULL, " ");
				timeout = atoi(parse);
			}
			else {
				timeout = -1;
			}
		}	
		
		for (int i=0; i<=nConns; i++) {
			// Recv request
			if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
				if (Recv_NonBlocking(peers[i].fd, connStat[i].data, CMD_LEN, &connStat[i], &peers[i]) < 0) {
					if (i == 0) {
						goto end;
					}
					RemoveConnection(i);
				}
				if (connStat[i].nRecv == CMD_LEN) {
					connStat[i].nRecv = 0;
					Log("%s\n", connStat[i].data);
					if (eof) {
						goto end;
					}
				}
			}
			
			// Send request
			if (peers[i].revents & POLLWRNORM) {
				if (connStat[i].nSent < CMD_LEN && (i == 0)) {
					//TODO WE ARE NOT GETTING HERE AFTER MULTIPLE COMMANDS WITHOUT DELAY printf("%s\n\n\n\n", connStat[i].dataSend);
					if (Send_NonBlocking(sock, connStat[i].dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
						Error("command sent incorrectly");
					}
					
					if (connStat[i].nSent == CMD_LEN) {
						connStat[i].nSent = 0;	
						peers[i].events |= POLLWRNORM;
						
						memset(connStat[i].dataSend, 0, CMD_LEN);
						if(getline(&line, &len, input) == -1) {
							Log("End of script reached, disconnecting from server...");
							eof = 1;
						}
						sprintf(connStat[i].dataSend, "%s", line);
						connStat[i].msg = cmdToMsg(connStat[i].dataSend);
						// Create a new data socket to service concurrent file send/receive
						if (connStat[i].msg == SENDF || connStat[i].msg == SENDF2) {
							createDataSocket(connStat[i].msg, connStat[i].dataSend);
							memset(connStat[i].dataSend, 0, CMD_LEN);
							sprintf(connStat[i].dataSend, "IDLE ");
							printf("%s\n", connStat[i].dataSend);
							connStat[i].msg = 0;
							continue;
						}
						if (connStat[i].msg == DELAY) {
							peers[i].events &= ~POLLWRNORM;
							
							char* parse = strtok(line, " ");
							parse = strtok(NULL, " ");
							timeout = atoi(parse);
						}
						else {
							timeout = -1;
						}
					}
				}
				else if (i > 0) {
					if (connStat[i].nStatSent < CMD_LEN) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
							Error("command sent incorrectly");
							RemoveConnection(i);
							continue;
						}
						if (connStat[i].nSent == CMD_LEN) {
							connStat[i].nStatSent = CMD_LEN;
							connStat[i].nSent = 0;
						}
					}
					
					if (connStat[i].nStatSent == CMD_LEN && connStat[i].nSent < connStat[i].filesize) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].file, connStat[i].filesize, &connStat[i], &peers[i]) < 0) {
							Error("command sent incorrectly");
						}
						if (connStat[i].nSent == connStat[i].filesize) {
							connStat[i].nStatSent = 0;
							connStat[i].nSent = 0;
						}
					}
				}
			}
		}
	}
	
	end: // If the connection to the server is lost on the command socket, go here
	
	// Close the input file after end of file
	if (fclose(input) < 0) {
		Error("Attempt to close input script failed.");
	}
	
	// After execution, allocated memory can be freed
	free(line);

	//Close socket
	close(sock);
	return 0;
}

