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
#include <time.h>

typedef unsigned char BYTE;

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
	RECVF,
	RECVF4,
	TERMINATE
} msg_type;

struct CONN_STAT {
	int msg;		//0 if idle/unknown
	int nRecv;
	int nCmdRecv;
	int nToRecv;
	int nSent;
	int nCmdSent;
	int nToSend;
	int ID;
	int loggedIn;
	int isFileRequest;
	char * file;
	char filename[MAX_FILENAME];
	char user[MAX_CRED];
	char fileUser[MAX_CRED];
	char fileRecip[MAX_CRED];
	char dataRecv[CMD_LEN];
	char dataSend[CMD_LEN];
};

// converting string (from script) to enumerated protocol message
msg_type strToMsg (char *msg) {
	if (!strcmp(msg, "IDLE"))
		return IDLE;
	else if (!strcmp(msg, "REGISTER"))
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
	else if (!strcmp(msg, "RECVF4"))
		return RECVF4;
	else if (!strcmp(msg, "TERMINATE"))
		return TERMINATE;
	else
		return -1;
}

char *timestamp;
int connID; // Running total of connection numbers
int nConns;	//total # of data sockets
struct pollfd peers[MAX_CONCURRENCY_LIMIT+1];	//sockets to be monitored by poll()
struct CONN_STAT connStat[MAX_CONCURRENCY_LIMIT+1];	//app-layer stats of the sockets

char * getTimestamp() {
	time_t timeNow;
	time(&timeNow);
	struct tm *now = localtime(&timeNow);
	
	sprintf(timestamp, "[%d:%d:%d]", now->tm_hour, now->tm_min, now->tm_sec);
	return timestamp;
}

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
	Log("%s: Connection with client (ID %d) closed.", getTimestamp(), connStat[i].ID);
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
		Log("%s: User attempted to register accound with credentials of invalid length.", getTimestamp());
		
		stat->nCmdRecv = 0;
				
		stat->nToSend = CMD_LEN;
		if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
			stat->nSent = 0;
			stat->nToSend = 0;
			return;
		}
		
		return;
	}		
	
	// If a user tries to name themselves after an internal command send an error
	//if (strToMsg(username) != -1) {
	//	sprintf(stat->dataSend, "ERROR '%s' is an invalid username because it is an internal server command. Please choose a new username.", username);
	//	//Log("%s ", getTimestamp());
	//				
	//	stat->nToSend = CMD_LEN;
	//	if (Send_NonBlocking(fd, stat->dataSend, stat->nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == stat->nToSend) {
	//		stat->nSent = 0;
	//		stat->nToSend = 0;
	//		return;
	//	}
	//		
	//	return;
	//}
	
	// Open the account file and check if there is already an account with the target username
	FILE *accts;
	accts = fopen("registered_accounts.txt", "a+");
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		
		// If there is already an account with a matching name send an error
		if (!strcmp(parse, username)) {
			sprintf(stat->dataSend, "ERROR User already exists with username '%s'. Please choose a new username.", username);
			Log("%s: User attempted to register an account with a username that already exists in the database.", getTimestamp());
					
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
	Log("%s: User successfully registered an account with username '%s'.", getTimestamp(), username);
	
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
	int logCheck = 0;
	char *line = (char *)malloc(sizeof(char) * 18);
	size_t len;
	char username[8];
	char password[9];
	
	// Make sure the client does not attempt to log in as another user while they are already logged in
	if (stat->loggedIn) {
		sprintf(stat->dataSend, "ERROR You are already logged in as '%s'.", stat->user);
		Log("%s: User '%s' tried to log in to another account while already logged in.", getTimestamp(), stat->user);
		
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
		// If the file fails to open, this almost certainly means the file hasn't been created yet
		// This happens only when the first user to create an account chosses a prohibited username
		Log("%s: Failed to open registered_accounts.txt. Did the user choose a prohibited username?", getTimestamp());
		return;
	}
	
	// Iterate through all accounts to find matching account
	while(getline(&line, &len, accts) != -1) {
		parse = strtok(line, " ");
		if (!strcmp(parse, username)) {
			// Check if user is already logged in
			for (int j=1; j<=nConns; j++) {
				if (!strcmp(username, connStat[j].user)) {
					logCheck = 1;
					sprintf(stat->dataSend, "ERROR User '%s' is already logged in.", username);
					Log("%s: User attempted to log in as a user that is currently logged in (%s).", getTimestamp(), username);
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
				sprintf(stat->dataSend, "LOGIN %s", username);
				Log("%s: User '%s' has successfully logged in.", getTimestamp(), username);
				break;
			}
		}
	}
	if (!stat->loggedIn && !logCheck) {
		sprintf(stat->dataSend, "ERROR Invalid user credentials.");
		Log("%s: User provided invalid password for account '%s'.", getTimestamp(), username);
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
		sprintf(stat->dataSend, "LOGOUT\n");
		printf("%s: User '%s' successfully logged out.", getTimestamp(), stat->user);
		memset(stat->user, 0, 8);
		stat->loggedIn = 0;
	}
	else {
		sprintf(stat->dataSend, "ERROR Cannot log out, you are not logged in.");
		Log("%s: User attempted to log out while already logged out.", getTimestamp());
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
	
	// Remove the newline character from the input script if it exists for formatting purposes
	int last = strlen(msg);
	if (msg[last-1] == '\n') {
		msg[last-1] = '\0';
	}
	
	// If not logged in, then do not allow message to be sent
	if (!stat->loggedIn) {
		sprintf(stat->dataSend, "ERROR Cannot send message, you are not logged in.");
		Log("%s: User attempted to send a message while logged out.", getTimestamp());
		stat->nToSend = CMD_LEN;
		if (Send_NonBlocking(fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
			stat->nSent = 0;
			stat->nToSend = 0;
		}
		return;
	}
	
	// Based on the type of message, format the message and send it to the appropriate recipients (sender is included for messages)
	switch (sel) {
		case SEND: {
			char * msgSend = (char *)malloc(sizeof(char) * CMD_LEN);
			sprintf(msgSend, "PRINT %s: %s", stat->user, msg);
			for (int j=1; j<=nConns; j++) {
				// Send the message to all online users
				if (connStat[j].loggedIn) {
					Log("%s: SERVER SENDING PUBLIC MESSAGE (%s->%s) - %s", getTimestamp(), stat->user, connStat[j].user, msg);
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
				Log("%s: User '%s' attempted to send a private message to themselves.", getTimestamp(), stat->user);
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
					sprintf(connStat[j].dataSend, "PRINT [%s->you]: %s", stat->user, sepMsg);
					Log("%s: SERVER SENDING PRIVATE MESSAGE (%s->%s) - %s", getTimestamp(), stat->user, target, sepMsg);
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
				sprintf(stat->dataSend, "ERROR Cannot send, user '%s' is not online.", target);
				Log("%s: User '%s' tried to send a private message to a user (%s) that is not logged in.", getTimestamp(), stat->user, target);
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
					Log("%s: SERVER SENDING ANONYMOUS PUBLIC MESSAGE (%s->%s) - %s", getTimestamp(), stat->user, connStat[j].user, msg);
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
				Log("%s: User '%s' attempted to send a private message to themselves.", getTimestamp(), stat->user);
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
					sprintf(connStat[j].dataSend, "PRINT [******->you]: %s", sepMsg);
					Log("%s: SERVER sending private anonymous message from '%s' to '%s': %s", getTimestamp(), stat->user, target, sepMsg);
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
				sprintf(stat->dataSend, "ERROR Cannot send, user '%s' is not online.", target);
				Log("%s: User '%s' tried to send a private message to a user (%s) that is not logged in.", getTimestamp(), stat->user, target);
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
	Log("%s: User '%s' requested the list of online users. Server responding with '%s'.", getTimestamp(), stat->user, msgResp);
	stat->nToSend = CMD_LEN;
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, stat, &peers[i]) < 0 || stat->nSent == CMD_LEN) {
		stat->nSent = 0;
		stat->nToSend = 0;
		return;
	}
}	

void recvf(struct CONN_STAT * stat, int i) {
	// Receive and save the file
	if (stat->nRecv < stat->nToRecv) {
		if (Recv_NonBlocking(peers[i].fd, stat->file, stat->nToRecv, stat, &peers[i]) < 0) {
			RemoveConnection(i);
			return;
		}
		if (stat->nRecv == stat->nToRecv) {
			stat->nRecv = 0;
			stat->nCmdRecv = 0;
			FILE * newFile; 
			
			// Open (create or replace) file with same filename on client-side
			if ((newFile = fopen(connStat[i].filename, "w")) == NULL) {
				Log("%s: Server received file from user '%s' but cannot create file '%s' in directory. Closing connection.", getTimestamp(), connStat[i].fileUser, connStat[i].filename);
				RemoveConnection(i);
				return;
			}
			
			// Write the data into the file
			int n;
			if ((n = fwrite(connStat[i].file, sizeof(char), connStat[i].nToRecv, newFile)) < connStat[i].nToRecv) {
				Log("%s: Incorrect number of bytes (%d/%d) written to file '%s'. Closing connection.", getTimestamp(), n, connStat[i].nToRecv, connStat[i].filename);
				RemoveConnection(i);
				return;
			}
			Log("%s: SERVER received file '%s' (%d bytes) from user '%s'.", getTimestamp(), connStat[i].filename, connStat[i].nToRecv, connStat[i].fileUser);
			
			// Free the allocated memory for the file and close the file pointer
			free(connStat[i].file);
			fclose(newFile);
			
			// Send a LISTEN command back to the clients in order to request a new data connection to be made for file transfer
			// Do not send file back to sender
			for (int j=1; j<=nConns; j++) {
				connStat[j].nToSend = CMD_LEN;
				if (connStat[j].loggedIn && strcmp(connStat[j].user, connStat[i].fileUser)) {
					sprintf(connStat[j].dataSend, "LISTEN %s %s %s", connStat[i].fileUser, connStat[j].user, connStat[i].filename);
					strcpy(connStat[j].filename, connStat[i].filename);
					Log("%s: SERVER sending command for user '%s' to request the file '%s' from '%s'.", getTimestamp(), connStat[j].user, connStat[i].filename, connStat[i].fileUser);
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						stat->nSent = 0;
						stat->nToSend = 0;
					}
				}
			}
			
			// After queueing messages to send to logged in clients, close this helper socket
			RemoveConnection(i);
		}
	}
}

void recvf4(struct CONN_STAT * stat, int i) {
	// Receive and save the file
	if (stat->nRecv < stat->nToRecv) {
		if (Recv_NonBlocking(peers[i].fd, stat->file, stat->nToRecv, stat, &peers[i]) < 0) {
			RemoveConnection(i);
			return;
		}
		if (stat->nRecv == stat->nToRecv) {
			stat->nRecv = 0;
			stat->nCmdRecv = 0;
			FILE * newFile; 
			
			// Open (create or replace) file with same filename on client-side
			if ((newFile = fopen(connStat[i].filename, "w")) == NULL) {
				Log("%s: Server received file from user '%s' but cannot create file '%s' in directory. Closing connection.", getTimestamp(), connStat[i].fileUser, connStat[i].filename);
				RemoveConnection(i);
			}
			
			// Write the data into the file
			int n;
			if ((n = fwrite(connStat[i].file, sizeof(char), connStat[i].nToRecv, newFile)) < connStat[i].nToRecv) {
				Log("%s: Incorrect number of bytes (%d/%d) written to file '%s'. Closing connection.", getTimestamp(), n, connStat[i].nToRecv, connStat[i].filename);
				RemoveConnection(i);
				return;
			}
			Log("%s: SERVER received file '%s' (%d bytes) from user '%s'.", getTimestamp(), connStat[i].filename, connStat[i].nToRecv, connStat[i].fileUser);
			
			// Free the allocated memory for the file and close the file pointer
			free(connStat[i].file);
			fclose(newFile);
			
			// Send a LISTEN command back to the target client only in order to request a new data connection to be made for file transfer
			for (int j=1; j<=nConns; j++) {
				connStat[j].nToSend = CMD_LEN;
				if (connStat[j].loggedIn && !strcmp(connStat[j].user, connStat[i].fileRecip)) {
					sprintf(connStat[j].dataSend, "LISTEN %s %s %s", connStat[i].fileUser, connStat[i].fileRecip, connStat[i].filename);
					strcpy(connStat[j].filename, connStat[i].filename);
					Log("%s: SERVER sending command for user '%s' to request the file '%s' from '%s'.", getTimestamp(), connStat[j].user, connStat[i].filename, connStat[i].fileUser);
					if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
						stat->nSent = 0;
						stat->nToSend = 0;
					}
				}
			}
			
			// After queueing messages to send to logged in clients, close this helper socket
			RemoveConnection(i);
		}
	}
}

void sendf(struct CONN_STAT * stat, int i, char * listen) {
	// Let the server know this socket will be sending a file
	stat->isFileRequest = 1;
	
	char *sender = strtok(listen, " ");
	char *receiver = strtok(NULL, " ");
	char *filename = strtok(NULL, "");
	
	// Remove the final newline character from the filename
	int last = strlen(filename);
	if (filename[last-1] == '\n')
		filename[last-1] = '\0';
	
	// Open the requested file to be read
	FILE * reqFile;
	if ((reqFile = fopen(filename, "r")) == NULL) {
		Log("%s: File '%s' not found in server database.", getTimestamp(), filename);
		RemoveConnection(i);
		return;
	}
	
	// Find the filesize of the file
	fseek(reqFile, 0, SEEK_END);
	stat->nToSend = ftell(reqFile);
	fseek(reqFile, 0, SEEK_SET);
	
	// Allocate memory to store the file
	stat->file = (char *)malloc(sizeof(char) * stat->nToSend);
	memset(stat->file, 0, stat->nToSend);
	
	// Close the file and open it again at lower level to read without dealing with buffers
	fclose(reqFile);
	int fd;
	if ((fd = open(filename, O_RDONLY)) == -1) {
		Log("%s: Server cannot open file '%s'. Closing connection.", getTimestamp(), filename);
	}
	
	// Attempt to read in the file into the allocated memory
	int n;
	if ((n = read(fd, stat->file, stat->nToSend)) != stat->nToSend) {
		Log("%s: Incorrect number of bytes (%d/%d) read from file '%s'. Closing connection.", getTimestamp(), n, connStat[i].nToRecv, filename);
		RemoveConnection(i);
		return;
	}
	
	// Close the requested file as it has already been read into memory
	close(fd);
	
	// Generate the command for the client to receive the file
	sprintf(stat->dataSend, "RECV %d %s", stat->nToSend, filename);
	Log("%s: SERVER sending file '%s' (%d bytes) from user '%s' to user '%s'.", getTimestamp(), filename, connStat[i].nToSend, sender, receiver);
	// Initiate file transfer by sending the message
	if (Send_NonBlocking(peers[i].fd, stat->dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == CMD_LEN) {
		peers[i].events |= POLLWRNORM;
		stat->nCmdSent = CMD_LEN;
		stat->nSent = 0;
	}
}

void termTransfer(struct CONN_STAT * stat, int i, char * user) {
	int last = strlen(user);
	if (user[last-1] == '\n')
		user[last-1] = '\0';
		
	Log("%s: SERVER ending file transfer process for user '%s'.", getTimestamp(), user);
	RemoveConnection(i);
	for (int j=1; j<=nConns; j++) {
		if (!strcmp(user, connStat[j].user)) {
			sprintf(connStat[j].dataSend, "IDLE");
			connStat[j].nToSend = CMD_LEN;
			if (Send_NonBlocking(peers[j].fd, connStat[j].dataSend, CMD_LEN, &connStat[j], &peers[j]) < 0 || connStat[j].nSent == CMD_LEN) {
				connStat[j].nSent = 0;
				connStat[j].nToSend = 0;
				return;
			}
		}
	}
}

// Based on the message received from the client, do something with the data
void protocol (struct CONN_STAT * stat, int i, char * body) {
	switch (stat->msg) {
		case IDLE:
			connStat[i].nCmdRecv = 0; // Intentionally do nothing
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
			sendf(stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		case LIST:
			list(stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case RECVF:
			recvf(stat, i);
			break;
		case RECVF4:
			recvf4(stat, i);
			connStat[i].nCmdRecv = 0;
			break;
		case TERMINATE:
			termTransfer(stat, i, body+1);
			connStat[i].nCmdRecv = 0;
			break;
		default:
			Log("%s: ERROR Unknown message from client!", getTimestamp());
	}
}

void DoServer(int svrPort) {
	// Create the nonblocking socket that listens for incoming connections
	int listenFD = socket(AF_INET, SOCK_STREAM, 0);
	if (listenFD < 0) {
		Error("Cannot create listening socket.");
	}
	SetNonBlockIO(listenFD);
	
	// Set the IP Adress and Port Number of the sockets to connect to
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(struct sockaddr_in));	
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Set the socket options and ignore the SIGPIPE signal
	int optval = 1;
	int r = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (r != 0) {
		Error("Cannot enable SO_REUSEADDR option.");
	}
	signal(SIGPIPE, SIG_IGN);

	// Bind the listening socket to the specified port number
	if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
		Error("Cannot bind to port %d.", svrPort);
	}
	
	// Listen to the listening socket for incoming connections
	if (listen(listenFD, 16) != 0) {
		Error("Cannot listen to port %d.", svrPort);
	}
	
	// Initialize global variable values and socket info structs
	connID = 0;
	nConns = 0;	
	memset(peers, 0, sizeof(peers));	
	peers[0].fd = listenFD;
	peers[0].events = POLLRDNORM;	
	memset(connStat, 0, sizeof(connStat));
	
	// The main loop for carrying out nonblocking operations
	while (1) {			
		// Poll for any events happening on any open connection
		r = poll(peers, nConns + 1, -1);	
		if (r < 0) {
			Error("Invalid poll() return value.");
		}			
		
		struct sockaddr_in clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);	
		
		// A new connection is being requested, accept and initialize info structs
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
		
		// For all data sockets, check what event has occured and on which socket
		for (int i=1; i<=nConns; i++) {
			// A data socket is requesting to receive data
			if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
				int fd = peers[i].fd;
				char * split;
				
				// Attempting to receive a command from the client
				if (connStat[i].nCmdRecv < CMD_LEN) {
					if (Recv_NonBlocking(fd, (BYTE *)&connStat[i].dataRecv, CMD_LEN, &connStat[i], &peers[i]) < 0) {
						RemoveConnection(i);
						continue;
					}
					
					// If full command has been received, parse it for what action to take next
					if (connStat[i].nRecv == CMD_LEN) {
						//printf("Connection %d: %s", connStat[i].ID, connStat[i].dataRecv);
						connStat[i].nCmdRecv = connStat[i].nRecv;
						connStat[i].nRecv = 0;
						
						// Insert null character to terminate string after command type
						split = strchr(connStat[i].dataRecv, ' ');
						if (split != NULL) {
							*split = '\0';
						}
		
						// Convert the command string to its corresponding enumerated value
						if ((connStat[i].msg = strToMsg(connStat[i].dataRecv)) == -1) {
							Log("%s: ERROR (conn %d): Unknown message %s received!", getTimestamp(), connStat[i].ID, connStat[i].dataRecv);
							RemoveConnection(i);
						}
						
						// If the received command is a file receive from the client, parse through the command to grab the sender, filesize, and filename
						if (connStat[i].msg == RECVF) {
							char *user = strtok(split+1, " ");
							char *filesize = strtok(NULL, " ");
							char *filename = strtok(NULL, " ");
							
							// Remove the final newline from the filename
							int len = strlen(filename);
							if (filename[len-1] == '\n') {
								filename[len-1] = '\0';
							}
							
							// Save user, filename, and filesize and allocate memory for receiving the file
							sprintf(connStat[i].fileUser, "%s", user);
							sprintf(connStat[i].filename, "%s", filename);
							connStat[i].nToRecv = atoi(filesize);
							connStat[i].file = (char *)malloc(sizeof(char) * connStat[i].nToRecv);
						}
						
						if (connStat[i].msg == RECVF4) {
							char *target = strtok(split+1, " ");
							char *source = strtok(NULL, " ");
							char *filesize = strtok(NULL, " ");
							char *filename = strtok(NULL, " ");
							
							// Remove the final newline from the filename
							int len = strlen(filename);
							if (filename[len-1] == '\n') {
								filename[len-1] = '\0';
							}
							
							// Save user, filename, and filesize and allocate memory for receiving the file
							sprintf(connStat[i].fileRecip, "%s", target);
							sprintf(connStat[i].fileUser, "%s", source);
							sprintf(connStat[i].filename, "%s", filename);
							connStat[i].nToRecv = atoi(filesize);
							connStat[i].file = (char *)malloc(sizeof(char) * connStat[i].nToRecv);
						}
					}
				}
				
				// Act on the received command
				if (connStat[i].nCmdRecv == CMD_LEN) {
					protocol(&connStat[i], i, split);
				}
				
			}
			
			//a previously blocked data socket becomes writable
			if (peers[i].revents & POLLWRNORM) {
				if (connStat[i].isFileRequest) {
					if (connStat[i].nCmdSent < CMD_LEN) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].dataSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
							Log("%s: Error sending LISTEN file request command to user '%s'. Closing connection with helper.", getTimestamp(), connStat[i].user);
							RemoveConnection(i);
						}
						if (connStat[i].nSent == CMD_LEN) {
							connStat[i].nCmdSent = CMD_LEN;
							connStat[i].nSent = 0;
						}
					}
					if (connStat[i].nCmdSent == CMD_LEN && connStat[i].nSent < connStat[i].nToSend) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].file, connStat[i].nToSend, &connStat[i], &peers[i]) < 0) {
							Log("%s: Error sending file '%s' to user '%s'. Closing connection with helper.", getTimestamp(), connStat[i].filename, connStat[i].user);
							RemoveConnection(i);
						}
						if (connStat[i].nSent == CMD_LEN) {
							Log("%s: SERVER successfully sent file '%s' (%d bytes) to user '%s'", getTimestamp(), connStat[i].filename, connStat[i].nToSend, connStat[i].user);
							connStat[i].nSent = 0;
							connStat[i].nCmdSent = 0;
							continue;
						}
					}
				}
				else {
					if (Send_NonBlocking(peers[i].fd, connStat[i].dataSend, connStat[i].nToSend, &connStat[i], &peers[i]) < 0 || connStat[i].nSent == connStat[i].nToSend) {
						connStat[i].nToSend = 0;
						connStat[i].nSent = 0;
						continue;
					}
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
	
	// Allocating memory for timestamp generation
	timestamp = (char *)malloc(sizeof(char) * 11);
	
	// grab the port number, or check if the server should reset its database
	int port = atoi(argv[1]);
	if (!strcmp(argv[1], "reset")) {
		if (remove("registered_accounts.txt") == 0) {
			Log("%s: Resetting accounts database.", getTimestamp());
			return 0;
		}
		else {
			Log("%s: Unable to delete account database. Is the file already deleted?", getTimestamp());
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
