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
#define MAX_CONCURRENCY_LIMIT 64

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

struct CONN_STAT {
	int msg;		//0 if idle/unknown
	int nRecv;
	int nCmdRecv;
	int nDataRecv;
	int nToRecv;
	int nSent;
	int nToSend;
	int loggedIn;
	char user[9];
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
	else
		return -1;
}

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

void RemoveConnection(int i) {
	close(peers[i].fd);	
	if (i < nConns) {	
		memmove(peers + i, peers + i + 1, (nConns-i) * sizeof(struct pollfd));
		memmove(connStat + i, connStat + i + 1, (nConns-i) * sizeof(struct CONN_STAT));
	}
	nConns--;
}

void reg(struct CONN_STAT * stat, int i, char * credentials) {
	int fd = peers[i].fd;
	char *line = (char *)malloc(sizeof(char) * 18);
	size_t len;
	char username[9];
	char password[9];
			
	// parse for username and password
	char *parse = strtok(credentials, " ");
	sprintf(username, "%s", parse);
	parse = strtok(NULL, " ");
	sprintf(password, "%s", parse);
	
	FILE *accts;
	accts = fopen("registered_accounts.txt", "a+");
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		if (!strcmp(parse, username)) {
			sprintf(stat->dataSend, "ERROR: User already exists with username '%s'. Please choose a new username.", username);
			Log("%s\n", stat->dataSend);
			
			stat->nCmdRecv = 0;
					
			stat->nToSend = CMD_LEN;
			if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
				stat->nSent = 0;
				stat->nToSend = 0;
				return;
			}
			
			return;
		}
	}
	
	fprintf(accts, "%s %s", username, password);
	fclose(accts);
	free(line);
	
	sprintf(stat->dataSend, "User '%s' registered successfully.", username);
	Log("%s\n", stat->dataSend);
	
	stat->nCmdRecv = 0;
	
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
	char username[9];
	char password[9];
			
	// parse for username and password
	char *parse = strtok(credentials, " ");
	sprintf(username, "%s", parse);
	parse = strtok(NULL, " ");
	sprintf(password, "%s", parse);
	
	FILE *accts;
	accts = fopen("registered_accounts.txt", "r");
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		if (!strcmp(parse, username)) {
			parse = strtok(NULL, " ");
			if (!strcmp(parse, password)) {
				strcpy(stat->user, username);
				stat->loggedIn = 1;
				sprintf(stat->dataSend, "Successfully logged in user '%s'.", username);
				Log("%s\n", stat->dataSend);
			}
		}
	}
	
	fclose(accts);
	free(line);
	
	if (!stat->loggedIn) {
		sprintf(stat->dataSend, "Invalid user credentials.");
		Log("%s\n", stat->dataSend);
	}
	
	stat->nCmdRecv = 0;
	
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void logout(struct CONN_STAT * stat, int i) {
	if (stat->loggedIn) {
		sprintf(stat->dataSend, "Logging out user '%s'. Thanks for using GopherChat!", stat->user);
		Log("%s\n", stat->dataSend);
		memset(stat->user, 0, 9);
		stat->loggedIn = 0;
	}
	else {
		sprintf(stat->dataSend, "Cannot log out, you are not logged in.");
		Log("%s\n", stat->dataSend);
	}
	
	stat->nToSend = CMD_LEN;
	
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}

void msg(int sel, struct CONN_STAT * stat, int i, char * msg) {
	int fd = peers[i].fd;
	
	switch (sel) {
		case 0: { // SEND
			char * msgSend = (char *)malloc(sizeof(char) * CMD_LEN);
			sprintf(msgSend, "%s: %s", stat->user, msg);
			for (int j=1; j<=nConns; j++) {
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
		case 1: {
			char *target = strtok(msg, " ");
			char *sepMsg = strtok(NULL, "");
			for (int j=1; j<=nConns; j++) {
				if (connStat[j].loggedIn && !strcmp(target, connStat[j].user)) {
					sprintf(connStat[j].dataSend, "[%s->%s]: %s", stat->user, connStat[j].user, sepMsg);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			
			sprintf(stat->dataSend, "[%s->%s]: %s", stat->user, target, sepMsg);
			stat->nToSend = CMD_LEN;
			if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
				stat->nSent = 0;
				stat->nToSend = 0;
			}
			break;
		}
		case 2: {
			char * msgSend = (char *)malloc(sizeof(char) * CMD_LEN);
			sprintf(msgSend, "******: %s", msg);
			for (int j=1; j<=nConns; j++) {
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
		case 3: {
			char *target = strtok(msg, " ");
			char *sepMsg = strtok(NULL, "");
			for (int j=1; j<=nConns; j++) {
				if (connStat[j].loggedIn && !strcmp(target, connStat[j].user)) {
					sprintf(connStat[j].dataSend, "[******->%s]: %s", stat->user, connStat[j].user, sepMsg);
					
					connStat[j].nToSend = CMD_LEN;
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						connStat[j].nSent = 0;
						connStat[j].nToSend = 0;
					}
				}
			}
			
			sprintf(stat->dataSend, "[******->%s]: %s", stat->user, target, sepMsg);
			
			stat->nToSend = CMD_LEN;
			if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
				stat->nSent = 0;
				stat->nToSend = 0;
			}
			break;
		}
	}
}

void list(struct CONN_STAT * stat, int i) {
	char msgResp[CMD_LEN];
	memset(msgResp, 0, CMD_LEN);
	
	for (int j=1; j<=nConns; j++) {
		if (connStat[j].loggedIn) {
			char userFormatted[11];
			
			if (strlen(msgResp) == 0)
				sprintf(userFormatted, "%s", connStat[j].user);
			else
				sprintf(userFormatted, ", %s", connStat[j].user);
				
			strcat(msgResp, userFormatted);
		}
	}
	
	sprintf(stat->dataSend, "Users online: %s", msgResp);
	printf("%s\n", stat->dataSend);
	
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
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
		case REGISTER:
			reg(stat, i, body+1);
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
			msg(0, stat, i, body+1);
			break;
		case SEND2:
			msg(1, stat, i, body+1);
			break;
		case SENDA:
			msg(2, stat, i, body+1);
			break;
		case SENDA2:
			msg(3, stat, i, body+1);
			break;
		case SENDF:
			//sendfile(0, stat, i);
			tempSend(stat, i, "sendf");
			connStat[i].nCmdRecv = 0;
			break;
		case SENDF2:
			//sendfile(1, stat, i);
			tempSend(stat, i, "sendf2");
			connStat[i].nCmdRecv = 0;
			break;
		case LIST:
			list(stat, i);
			connStat[i].nCmdRecv = 0;
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
						printf("Connection %d: %s", i, connStat[i].dataRecv);
						connStat[i].nCmdRecv = connStat[i].nRecv;
						connStat[i].nRecv = 0;					
						
						// Insert null character to terminate string after command type
						split = strchr(connStat[i].dataRecv, ' ');
						if (split != NULL) {
							*split = '\0';
						}
		
						// Convert the command string to its corresponding enumerated value
						if ((connStat[i].msg = strToMsg(connStat[i].dataRecv)) == -1) {
							Log("ERROR: Unknown message %d", connStat[i].msg);
							continue;
						}
					}
				}
				
				if (connStat[i].nCmdRecv == CMD_LEN) {
					protocol(&connStat[i], i, split);
					connStat[i].nCmdRecv = 0;
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
	return 0;
}
