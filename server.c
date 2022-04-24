//Non-blocking server
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

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

#define MAX_REQUEST_SIZE 10000000
#define CMD_LEN 300
#define MAX_CONCURRENCY_LIMIT 18
#define MAX_FILENAME 32
#define MIN_CRED 4
#define MAX_CRED 8

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
	DELAY,
	RECVF
} msg_type;

struct CONN_STAT {
	int msg;		//0 if idle/unknown
	int nRecv;
	int nCmdRecv;
	int nDataRecv;
	int nToRecv;
	int nSent;
	int nToSend;
	int ID;
	int loggedIn;
	char * file;
	char filename[MAX_FILENAME];
	char user[MAX_CRED];
	char dataRecv[CMD_LEN];
	char dataSend[CMD_LEN];
};

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
	else if (!strcmp(msg, "RECVF"))
		return RECVF;
	else
		return -1;
}

int connID; // Running total of connection numbers
int nConns;	//total # of data sockets
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

int Send_NonBlocking(int sockFD, const BYTE * data, int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {	
	while (pStat->nSent < len) {
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

int Recv_NonBlocking(int sockFD, BYTE * data, int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {
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
	Log("Connection %d closed. (Position %d in struct array)", connStat[i].ID, i);
	close(peers[i].fd);	
	if (i < nConns) {	
		memmove(peers + i, peers + i + 1, (nConns-i) * sizeof(struct pollfd));
		memmove(connStat + i, connStat + i + 1, (nConns-i) * sizeof(struct CONN_STAT));
	}
	nConns--;
}

void reg(struct CONN_STAT * stat, int i, char * credentials) {
	int fd = peers[i].fd;
	char *line = (char *)malloc(sizeof(char) * CMD_LEN);
	size_t len;
	char username[64];
	char password[64];
			
	// parse for username and password
	char *parse = strtok(credentials, " ");
	sprintf(username, "%s", parse);
	parse = strtok(NULL, " ");
	sprintf(password, "%s", parse);
	
	int uLen = strlen(username);
	int pLen = strlen(password) - 1; // Accounting for newline from command
	
	// Checking if the username and password are valid sizes
	if (uLen < MIN_CRED || uLen > MAX_CRED || pLen < MIN_CRED || pLen > MAX_CRED) {
		sprintf(stat->dataSend, "ERROR Credentials are of invalid size (must be between 4 and 8 characters). Username is %d characters and password is %d characters.", uLen, pLen);
		Log("%s", stat->dataSend);
		
		stat->nCmdRecv = 0;
				
		stat->nToSend = CMD_LEN;
		if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
			stat->nSent = 0;
			stat->nToSend = 0;
			return;
		}
		
		return;
	}
	
	// Open the account file and check if there is already an account with the target username
	FILE *accts;
	accts = fopen("registered_accounts.txt", "a+");
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		
		// If there is already an account with a matching name send an error
		if (!strcmp(parse, username)) {
			sprintf(stat->dataSend, "ERROR User already exists with username '%s'. Please choose a new username.", username);
			Log("%s", stat->dataSend);
					
			stat->nToSend = CMD_LEN;
			if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
				stat->nSent = 0;
				stat->nToSend = 0;
				return;
			}
			
			return;
		}
		
		// If a user tries to name themselves after an internal command send an error
		if (strToMsg(username) != -1) {
			sprintf(stat->dataSend, "ERROR '%s' is an invalid username because it is an internal server command. Please choose a new username.", username);
			Log("%s", stat->dataSend);
					
			stat->nToSend = CMD_LEN;
			if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
				stat->nSent = 0;
				stat->nToSend = 0;
				return;
			}
			
			return;
		}
	}
	
	// Save the username and password of the new account to the accounts file, then close it and free the line buffer
	fprintf(accts, "%s %s", username, password);
	fclose(accts);
	free(line);
	
	// Format a success message and send it back to the client
	sprintf(stat->dataSend, "PRINT User '%s' registered successfully.", username);
	Log("%s", stat->dataSend);
	
	// Initiate sending the success message back to the client
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void login(struct CONN_STAT * stat, int i, char * credentials) {
	int fd = peers[i].fd;
	char *line = (char *)malloc(sizeof(char) * 18);
	size_t len;
	char username[8];
	char password[9];
	
	// Make sure the client does not attempt to log in as another user while they are already logged in
	if (stat->loggedIn) {
		sprintf(stat->dataSend, "ERROR You are already logged in as '%s'.", stat->user);
		Log("%s", stat->dataSend);
		
		stat->nToSend = CMD_LEN;
		if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
			stat->nSent = 0;
			stat->nToSend = 0;
			return;
		}
	}
			
	// parse for username and password
	char *parse = strtok(credentials, " ");
	sprintf(username, "%s", parse);
	parse = strtok(NULL, " ");
	sprintf(password, "%s", parse);
	
	// Open the accounts file to check if the user exists
	FILE *accts;
	if((accts = fopen("registered_accounts.txt", "r")) == NULL) {
		
	}
	
	// Iterate through all accounts to find matching account
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		if (!strcmp(parse, username)) {
			int logCheck = 0;
			// Check if user is already logged in
			for (int j=1; j<=nConns; j++) {
				if (!strcmp(username, connStat[j].user)) {
					logCheck = 1;
					sprintf(stat->dataSend, "ERROR User '%s' is already logged in.", username);
					Log("%s", stat->dataSend);
					break;
				}
			}
			if (logCheck) {
				break;
			}
			
			// Check to make sure the correct password was supplied. If it was, store username and set state to logged in
			parse = strtok(NULL, " ");
			if (!strcmp(parse, password)) {
				// Relay that the user has logged in to all other online users
				for (int j=1; j<=nConns; j++) {
					if (connStat[j].loggedIn) {
						sprintf(connStat[j].dataSend, "PRINT '%s' has logged in.", username);
						connStat[j].nToSend = CMD_LEN;
						if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
							connStat[j].nSent = 0;
							connStat[j].nToSend = 0;
						}
					}
				}	
			
				// Log in the user
				strcpy(stat->user, username);
				stat->loggedIn = 1;
				sprintf(stat->dataSend, "PRINT Successfully logged in user '%s'.", username);
				Log("%s", stat->dataSend);
				break;
			}
			else {
				sprintf(stat->dataSend, "ERROR Invalid user credentials.");
				Log("%s", stat->dataSend);
				break;
			}
		}
	}
	
	// Close the accounts file and free the line buffer
	fclose(accts);
	free(line);
	
	// Send the appropriate message back to the client
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void logout(struct CONN_STAT * stat, int i) {
	// Make sure the user is logged in first before logging them out, otherwise return an error message
	if (stat->loggedIn) {
		sprintf(stat->dataSend, "PRINT Logging out user '%s'. Thanks for using GopherChat!", stat->user);
		Log("%s", stat->dataSend);
		memset(stat->user, 0, 8);
		stat->loggedIn = 0;
	}
	else {
		sprintf(stat->dataSend, "ERROR Cannot log out, you are not logged in.");
		Log("%s", stat->dataSend);
	}
	
	// Send the response message back to the client
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void msg(int sel, struct CONN_STAT * stat, int i, char * msg) {
	int fd = peers[i].fd;
	
	// Remove the newline character from teh input script if it exists for formatting purposes
	int last = strlen(msg);
	if (msg[last-1] == '\n') {
		msg[last-1] = '\0';
	}
	
	// Based on the type of message, format the message and send it to the appropriate recipients (sender is included for messages)
	switch (sel) {
		case SEND: {
			char * msgSend = (char *)malloc(sizeof(char) * CMD_LEN);
			sprintf(msgSend, "PRINT %s: %s", stat->user, msg);
			for (int j=1; j<=nConns; j++) {
				// Send the message to all online users
				if (connStat[j].loggedIn) {
					strcpy(connStat[j].dataSend, msgSend);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			free(msgSend);
			break;
		}
		case SEND2: {
			char *target = strtok(msg, " ");
			char *sepMsg = strtok(NULL, "");
			int userOnline = 0;
			
			// If the user is attempting to send a private message to themselves, send an error message
			if (!strcmp(stat->user, target)) {
				sprintf(stat->dataSend, "ERROR You are attempting to send a private message to yourself.");
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
				break;
			}
			
			// Search through all connections to find the target user
			for (int j=1; j<=nConns; j++) {
				// If the user is online, send them the private message
				if (connStat[j].loggedIn && !strcmp(target, connStat[j].user)) {
					userOnline = 1;
					sprintf(connStat[j].dataSend, "PRINT [%s->%s]: %s", stat->user, connStat[j].user, sepMsg);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			
			// Send the sender the appropriate message based on if the target is online
			if (userOnline) {
				sprintf(stat->dataSend, "PRINT [you->%s]: %s", target, sepMsg);
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
			}
			else {
				sprintf(stat->dataSend, "ERROR User '%s' is not online.", target);
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
			}
			break;
		}
		case SENDA: {
			char * msgSend = (char *)malloc(sizeof(char) * CMD_LEN);
			sprintf(msgSend, "PRINT ******: %s", msg);
			for (int j=1; j<=nConns; j++) {
				// Send the anonymous message to all online users
				if (connStat[j].loggedIn) {
					strcpy(connStat[j].dataSend, msgSend);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			
			free(msgSend);
			break;
		}
		case SENDA2: {
			char *target = strtok(msg, " ");
			char *sepMsg = strtok(NULL, "");
			int userOnline = 0;
			
			// If the user is attempting to send a private message to themselves, send an error message
			if (!strcmp(stat->user, target)) {
				sprintf(stat->dataSend, "ERROR You are attempting to send a private message to yourself.");
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
				break;
			}
			
			// Search through all connections to find the target user
			for (int j=1; j<=nConns; j++) {
				// If the user is online, send them the anonymous private message
				if (connStat[j].loggedIn && !strcmp(target, connStat[j].user)) {
					userOnline = 1;
					sprintf(connStat[j].dataSend, "PRINT [******->%s]: %s", connStat[j].user, sepMsg);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			
			// Send the sender the appropriate message based on if the target is online
			if (userOnline) {
				sprintf(stat->dataSend, "PRINT [(you)->%s]: %s", target, sepMsg);
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
			}
			else {
				sprintf(stat->dataSend, "ERROR User '%s' is not online.", target);
				stat->nToSend = CMD_LEN;
				if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
					stat->nSent = 0;
					stat->nToSend = 0;
				}
			}
			break;
		}
	}
}

void list(struct CONN_STAT * stat, int i) {
	char msgResp[CMD_LEN];
	memset(msgResp, 0, CMD_LEN);
	
	// Iterate through all open connections for logged in users
	for (int j=1; j<=nConns; j++) {
		if (connStat[j].loggedIn) {
			char userFormatted[11];
			
			// If the user is logged in, add then to the formatted list
			if (strlen(msgResp) == 0)
				sprintf(userFormatted, "%s", connStat[j].user);
			else
				sprintf(userFormatted, ", %s", connStat[j].user);
				
			strcat(msgResp, userFormatted);
		}
	}
	
	// Save the formatted userlist in the send buffer and send it back to the client
	sprintf(stat->dataSend, "PRINT Users online: %s", msgResp);
	printf("%s\n", stat->dataSend);
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}	

void recvf(struct CONN_STAT * stat, int i) {

	if (stat->nRecv < stat->nToRecv) {
		if (Recv_NonBlocking(peers[i].fd, stat->file, stat->nToRecv, stat, &peers[i]) < 0) {
			RemoveConnection(i);
			return;
		}
		
		if (stat->nRecv == stat->nToRecv) {
			stat->nRecv = 0;
			stat->nCmdRecv = 0;
			FILE * newFile; 
			
			if ((newFile = fopen(connStat[i].filename, "w")) == NULL) {
				Log("File cannot open");
				RemoveConnection(i);
			}
			else {
				Log("file '%s' opened successfully.", connStat[i].filename);
			}
			
			int n;
			if ((n = fwrite(connStat[i].file, sizeof(char), connStat[i].nToRecv, newFile)) < connStat[i].nToRecv) {
				Log("Incorrect bytes written %d/%d", n, connStat[i].nToRecv);
				RemoveConnection(i);
			}
			else if (n == connStat[i].nToRecv) {
				Log("%d bytes written successfully to '%s'.", n, connStat[i].filename);
			}
			
			free(connStat[i].file);
			fclose(newFile);
			RemoveConnection(i);
		}
	}
}

void tempSend(struct CONN_STAT * stat, int i, char * str) {
	sprintf(stat->dataSend, "%s", str);
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void protocol (struct CONN_STAT * stat, int i, char * body) {
	switch (stat->msg) {
		case IDLE:
			printf("IDLE received\n");
			connStat[i].nCmdRecv = 0;
			break;
		case REGISTER:
			reg(stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case LOGIN:
			login(stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case LOGOUT:
			logout(stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case SEND:
			msg(SEND, stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case SEND2:
			msg(SEND2, stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case SENDA:
			msg(SENDA, stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case SENDA2:
			msg(SENDA2, stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case SENDF:
			//sendfile(0, stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case SENDF2:
			//sendfile(1, stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case LIST:
			list(stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case RECVF:
			recvf(stat, i);
			break;
	}
}

void DoServer(int svrPort) {
	BYTE * buf = (BYTE *)malloc(MAX_REQUEST_SIZE);
	memset(buf, 0, MAX_REQUEST_SIZE);	
	
	int listenFD = socket(AF_INET, SOCK_STREAM, 0);
	if (listenFD < 0) {
		Error("Cannot create listening socket.");
	}
	SetNonBlockIO(listenFD);
	
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(struct sockaddr_in));	
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	int optval = 1;
	int r = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (r != 0) {
		Error("Cannot enable SO_REUSEADDR option.");
	}
	signal(SIGPIPE, SIG_IGN);

	if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
		Error("Cannot bind to port %d.", svrPort);
	}
	
	if (listen(listenFD, 16) != 0) {
		Error("Cannot listen to port %d.", svrPort);
	}
	
	connID = 0;
	nConns = 0;	
	memset(peers, 0, sizeof(peers));	
	peers[0].fd = listenFD;
	peers[0].events = POLLRDNORM;	
	memset(connStat, 0, sizeof(connStat));
	
	int connID = 0;
	while (1) {	//the main loop		
		//monitor the listening sock and data socks, nConn+1 in total
		int temp;
		r = poll(peers, nConns + 1, -1);	
		if (r < 0) {
			Error("Invalid poll() return value.");
			continue;
		}			
			
		struct sockaddr_in clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);	
		
		//new incoming connection
		if ((peers[0].revents & POLLRDNORM) && (nConns < MAX_CONCURRENCY_LIMIT)) {					
			int fd = accept(listenFD, (struct sockaddr *)&clientAddr, &clientAddrLen);
			if (fd != -1) {
				SetNonBlockIO(fd);
				nConns++;
				peers[nConns].fd = fd;
				peers[nConns].events = POLLRDNORM;
				peers[nConns].revents = 0;
				
				memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
				connStat[nConns].ID = ++connID;
			}
		}
		
		for (int i=1; i<=nConns; i++) {
			if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
				int fd = peers[i].fd;
				char * split;
				
				// protocol message type recv request
				if (connStat[i].nCmdRecv < CMD_LEN) {
					if ((temp = Recv_NonBlocking(fd, (BYTE *)&connStat[i].dataRecv, CMD_LEN, &connStat[i], &peers[i])) < 0) {
						RemoveConnection(i);
						continue;
					}
					
					if (connStat[i].nRecv == CMD_LEN) {
						printf("Connection %d: %s", connStat[i].ID, connStat[i].dataRecv);
						connStat[i].nCmdRecv = connStat[i].nRecv;
						connStat[i].nRecv = 0;					
						
						// Insert null character to terminate string after command type
						split = strchr(connStat[i].dataRecv, ' ');
						if (split != NULL) {
							*split = '\0';
						}
		
						// Convert the command string to its corresponding enumerated value
						if ((connStat[i].msg = strToMsg(connStat[i].dataRecv)) == -1) {
							Log("ERROR (conn %d): Unknown message %d", i, connStat[i].msg);
							RemoveConnection(i);
						}
						
						if (connStat[i].msg == RECVF) {
							char *filesize = strtok(split+1, " ");
							char *filename = strtok(NULL, " ");
							sprintf(connStat[i].filename, "%s", filename);
							connStat[i].nToRecv = atoi(filesize);
							connStat[i].file = (char *)malloc(sizeof(char) * connStat[i].nToRecv);
						}
					}
				}
				
				// Act on the message received
				if (connStat[i].nCmdRecv == CMD_LEN) {
					protocol(&connStat[i], i, split);
				}
				
			}
			
			//a previously blocked data socket becomes writable
			if (peers[i].revents & POLLWRNORM) {
				//int msg = connStat[i].msg;
				if (Send_NonBlocking(peers[i].fd, connStat[i].dataSend, connStat[i].nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == connStat[i].nToSend) {
					connStat[i].nToSend = 0;
					connStat[i].nSent = 0;
					continue;
				}
			}

		}
	}	
}

int main(int argc, char * * argv) {	
	if (argc != 2) {
		Log("Usage: %s [server Port]/['reset']", argv[0]);
		return -1;
	}
	
	// grab the port number, or check if the server should reset its database
	int port = atoi(argv[1]);
	if (!strcmp(argv[1], "reset")) {
		if (remove("registered_accounts.txt") == 0) {
			Log("Resetting database.");
			return 0;
		}
		else {
			Log("Unable to delete account database. Is the file already deleted?");
			return -1;
		}
	}
	else if(port == 0) {
		Log("Usage: %s [server Port]/['reset']", argv[0]);
		return -1;
	}
	
	// perform server actions on specified port
	DoServer(port);
	
	// this should never be reached
	return EXIT_FAILURE;
}
