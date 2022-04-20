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
#define DATA_FRAME_LEN 275
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
	int nToRecv;
	int nMsgRecv;
	int nDataRecv;
	int nToSend;
	int nSent;
	char data[MAX_REQUEST_SIZE];
};

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
				
				// protocol message type recv request
				if (connStat[i].nMsgRecv < sizeof(msg_type)) {
					if ((temp = Recv_NonBlocking(fd, (BYTE *)&connStat[i].msg, sizeof(msg_type), &connStat[i], &peers[i])) < 0) {
						Log("received %d", temp);
						RemoveConnection(i);
						continue;
					}
					
					if (connStat[i].nRecv == sizeof(msg_type)) {
						Log("%d bytes received", connStat[i].nRecv);
						connStat[i].nToRecv = DATA_FRAME_LEN;
						connStat[i].nMsgRecv = connStat[i].nRecv;
						connStat[i].nRecv = 0;
						Log("%d", connStat[i].msg);
					}
				}
				
				// protocol data recv request
				if (connStat[i].nDataRecv < connStat[i].nToRecv) {
					if ((temp = Recv_NonBlocking(fd, connStat[i].data, connStat[i].nToRecv, &connStat[i], &peers[i])) < 0) {
						Log("received %d", temp);
						RemoveConnection(i);
						continue;
					}
					
					if (connStat[i].nRecv == connStat[i].nToRecv) {
						Log("%d bytes received", connStat[i].nRecv);
						connStat[i].nToSend = DATA_FRAME_LEN;
						connStat[i].nDataRecv = connStat[i].nRecv;
						connStat[i].nRecv = 0;
						printf("%s", connStat[i].data);
					}
				}
				
				if (connStat[i].nToSend != 0) {
					if ((temp = Send_NonBlocking(peers[i].fd, connStat[i].data, connStat[i].nToSend, &connStat[i], &peers[i])) < 0 || connStat[i].nSent == connStat[i].nToSend) {
						//Log("Disconnecting");
						Log("sent %d", connStat[i].nSent);
						connStat[i].nToSend = 0;
						connStat[i].nSent = 0;
						connStat[i].nMsgRecv = 0;
						connStat[i].nDataRecv = 0;
						
						//RemoveConnection(i);
						continue;
					}
				}
				
			}
			
			//a previously blocked data socket becomes writable
			if (peers[i].revents & POLLWRNORM) {
				//int msg = connStat[i].msg;
				if (Send_NonBlocking(peers[i].fd, connStat[i].data, connStat[i].nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == connStat[i].nToSend) {
					//Log("Disconnecting");
					Log("%d", connStat[i].nSent);
						connStat[i].nToSend = 0;
						connStat[i].nSent = 0;
						connStat[i].nMsgRecv = 0;
						connStat[i].nDataRecv = 0;
					//RemoveConnection(i);
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
