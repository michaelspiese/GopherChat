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

#define MAX_REQUEST_SIZE 10000000
#define CMD_LEN 300
#define MAX_CONCURRENCY_LIMIT 8

typedef unsigned char BYTE;

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
	DELAY,
	PRINT,
	ERROR,
	LISTEN,
	RECV
} msg_type;

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
	else if (!strcmp(msg, "PRINT"))
		return PRINT;
	else if (!strcmp(msg, "ERROR"))
		return ERROR;
	else if (!strcmp(msg, "LISTEN"))
		return LISTEN;
	else if (!strcmp(msg, "RECV"))
		return RECV;
	else
		return -1;
}

struct CONN_STAT {
	int msg;
	int nRecv;
	int nCmdRecv;
	int nSent;
	int nStatSent;
	int filesize;
	int loggedIn;
	char *file;
	char user[8];
	char filename[33];
	char cmdSend[CMD_LEN];
	char cmdRecv[CMD_LEN];
};

int eof;
int connected;
int timeout;
int nConns;
char *timestamp;
struct pollfd peers[MAX_CONCURRENCY_LIMIT+1];	//sockets to be monitored by poll()
struct CONN_STAT connStat[MAX_CONCURRENCY_LIMIT+1];	//app-layer stats of the sockets
struct sockaddr_in serverAddr;

// returns a pointer to a timestamp with the current time when called
char * getTimestamp() {
	time_t timeNow;
	time(&timeNow);
	struct tm *now = localtime(&timeNow);
	
	sprintf(timestamp, "[%02d:%02d:%02d]", now->tm_hour, now->tm_min, now->tm_sec);
	return timestamp;
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

	// Temporarily change the first space into a null character
	char *split = strchr(str, ' ');
	if (split != NULL)
		*split = '\0';
	
	// Convert the command string to its corresponding enumerated value
	if ((msg = strToMsg(str)) == -1) {
		Log("ERROR: Unknown message %d", msg);
		return -1;
	}
	
	// Return the space
	if (split != NULL)
		*split = ' ';
	
	return msg;
}

int Send_NonBlocking(int sockFD, const BYTE * data, int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {	
	while (pStat->nSent < len) {
		int n = send(sockFD, data + pStat->nSent, len - pStat->nSent, 0);
		if (n >= 0) {
			pStat->nSent += n;
		} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
			close(sockFD);
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) {
			//The socket becomes non-writable. Exit now to prevent blocking. 
			//OS will notify us when we can write
			pPeer->events |= POLLWRNORM; 
			return 0; 
		} else {
			Log("Unexpected send error %d: %s", errno, strerror(errno));
			exit(-1);
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
			close(sockFD);
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) { 
			//The socket becomes non-readable. Exit now to prevent blocking. 
			//OS will notify us when we can read
			return 0; 
		} else if (errno == ECONNREFUSED) {
			Log("Unable to connect to server. Is it running?");
			close(sockFD);
			return -1;
		} else {
			Log("Unexpected recv error %d: %s.", errno, strerror(errno));
			exit(-1);
		}
	}
	
	return 0;
}

void SetNonBlockIO(int fd) {
	int val = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, val | O_NONBLOCK) != 0) {
		Log("Cannot set nonblocking I/O.");
		exit(-1);
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

// log in the user on the client side
void login(int i, char * user) {
	sprintf(connStat[i].user, "%s", user);
	connStat[i].loggedIn = 1;
	Log("Successfully logged in with user '%s'.", connStat[i].user);
}

// Log out the user on the client side
void logout(int i) {
	Log("Logging out user '%s'. Thanks for using GopherChat!", connStat[i].user);
	connStat[i].loggedIn = 0;
	memset(connStat[i].user, 0, 8);
}

// Create a socket connection to send a file to the server
void createDataSocket(int type, char *cmd) {
	// Create a non-blocking socket and connect it to the server
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int conn = connect(fd, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	SetNonBlockIO(fd);
	if (fd != -1) {
		// If this succeeds, increase number of connections and initialize all info structs
		++nConns;
		peers[nConns].fd = fd;
		peers[nConns].events = POLLWRNORM | POLLRDNORM;
		peers[nConns].revents = 0;
		memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
		
		// If command if SENDF, parse command for filename
		if (type == SENDF) {
			char* parse = strtok(cmd, " ");
			parse = strtok(NULL, "");
			sprintf(connStat[nConns].filename, "%s", parse);
			
			
			// Replace final newline with terminating null character
			int last = strlen(connStat[nConns].filename);
			if (connStat[nConns].filename[last-1] = '\n') 
				connStat[nConns].filename[last-1] = '\0';
			
			// Attempt to open the file. If it doesnt exist, remove new connection
			FILE * file;
			if ((file = fopen(connStat[nConns].filename, "r")) == NULL) {
				Log("ERROR: Cannot open file '%s'. Does it exist?", connStat[nConns].filename);
				RemoveConnection(nConns);
				return;
			}
			
			// Find the size of the file
			fseek(file, 0, SEEK_END);
			connStat[nConns].filesize = ftell(file);
			fseek(file, 0, SEEK_SET);
			
			// Allocate memory of the same size as the file and save the file into it
			connStat[nConns].file = (char *)malloc(sizeof(char) * connStat[nConns].filesize);
			memset(connStat[nConns].file, 0, connStat[nConns].filesize);
			
			// Make sure the correct number of bits has been written into the buffer
			int n;
			if ((n = fread(connStat[nConns].file, sizeof(char), connStat[nConns].filesize, file)) != connStat[nConns].filesize) {
				Log("ERROR: File read incorrectly (%d/%d bytes)", n, connStat[nConns].filesize);
				RemoveConnection(nConns);
				return;
			}
			
			// Close the new file as it has been saved into memory
			fclose(file);
			
			// Write a command consisting of the filesize to transmit and the name of the file
			sprintf(connStat[nConns].cmdSend, "RECVF %s %d %s\n", connStat[0].user, connStat[nConns].filesize, connStat[nConns].filename);
		}
		if (type == SENDF2) {
			char *target = strtok(cmd, " ");
			target = strtok(NULL, " ");
			char *filename = strtok(NULL, "");
			sprintf(connStat[nConns].filename, "%s", filename);
			
			// Replace final newline with terminating null character
			int last = strlen(connStat[nConns].filename);
			if (connStat[nConns].filename[last-1] = '\n') 
				connStat[nConns].filename[last-1] = '\0';
			
			// Attempt to open the file. If it doesnt exist, remove new connection
			FILE * file;
			if ((file = fopen(connStat[nConns].filename, "r")) == NULL) {
				Log("ERROR: Cannot open file '%s'. Does it exist?", connStat[nConns].filename);
				RemoveConnection(nConns);
				return;
			}
			
			// Find the size of the file
			fseek(file, 0, SEEK_END);
			connStat[nConns].filesize = ftell(file);
			fseek(file, 0, SEEK_SET);
			
			// If the file is over 10000000 bytes, it cannot be sent
			if (connStat[nConns].filesize > MAX_REQUEST_SIZE) {
				Log("ERROR: This file is %d bytes, which is larger than the maximum file size of 10MB.");
				fclose(file);
				RemoveConnection(nConns);
				return;
			}
			
			// Allocate memory of the same size as the file and save the file into it
			connStat[nConns].file = (char *)malloc(sizeof(char) * connStat[nConns].filesize);
			memset(connStat[nConns].file, 0, connStat[nConns].filesize);
			
			// Make sure the correct number of bytes has been written into the buffer
			int n;
			if ((n = fread(connStat[nConns].file, sizeof(char), connStat[nConns].filesize, file)) != connStat[nConns].filesize) {
				Log("ERROR: File read incorrectly (%d/%d bytes)", n, connStat[nConns].filesize);
				fclose(file);
				RemoveConnection(nConns);
				return;
			}
			
			// Close the new file as it has been saved into memory
			fclose(file);
			
			// Write a command consisting of the filesize to transmit and the name of the file
			sprintf(connStat[nConns].cmdSend, "RECVF4 %s %s %d %s\n", target, connStat[0].user, connStat[nConns].filesize, connStat[nConns].filename);
		}
	}
}

// Create a socket connection to request a file from the server
void reqSock (char * reqFile) {	
	// Create a non-blocking socket and connect it to the server
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int conn = connect(fd, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	SetNonBlockIO(fd);
	if (fd != -1) {
		// If this succeeds, increase number of connections and initialize all info structs
		++nConns;
		peers[nConns].fd = fd;
		peers[nConns].events = POLLWRNORM | POLLRDNORM;
		peers[nConns].revents = 0;
		memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
		
		// Write a command requesting the file from the server
		sprintf(connStat[nConns].cmdSend, "SENDF %s\n", reqFile);
	}
}

// Receive a file from the server
void recvf(int i) {
	// Receive the file from the server and write it to a new file in the client directory
	if (connStat[i].nRecv < connStat[i].filesize) {
		if (Recv_NonBlocking(peers[i].fd, connStat[i].file, connStat[i].filesize, &connStat[i], &peers[i]) < 0) {
			Log("ERROR: Receive from server failed.");
			RemoveConnection(i);
			return;
		}
		if (connStat[i].nRecv == connStat[i].filesize) {
			// Create a new file in write mode with the same filename as the client's copy. Overwrite if file with filename exists already 
			FILE * newFile;
			if ((newFile = fopen(connStat[i].filename, "w")) == NULL) {
				Log("ERROR: Cannot open new file '%s'.", connStat[i].filename);
				fclose(newFile);
				free(connStat[i].file);
				RemoveConnection(i);
				return;
			}
			
			// Write the data received from the server to the new file
			int n;
			if ((n = fwrite(connStat[i].file, sizeof(char), connStat[i].filesize, newFile)) < connStat[i].filesize) {
				Log("ERROR: Incorrect number of bytes (%d/%d) written to file.", n, connStat[i].filesize);
				fclose(newFile);
				free(connStat[i].file);
				RemoveConnection(i);
				return;
			}
			Log("INFO: Successfully received file '%s' (%d bytes).", connStat[i].filename, connStat[i].filesize, connStat[i].user);
		
			// Free resources and close the file;
			fclose(newFile);
			free(connStat[i].file);
			connStat[i].nCmdRecv = 0;
			connStat[i].nRecv = 0;

			// Send terminate command back to the server to finalize file transfer process
			sprintf(connStat[i].cmdSend, "TERMINATE %s\n", connStat[0].user);
			if (Send_NonBlocking(peers[i].fd, connStat[i].cmdSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
				Log("Command sent incorrectly");
				RemoveConnection(i);
			}
		}
	}
}

// Choose which actions to take based on which command has been received
void protocol(char * cmdRecv, int i) {
	char * command = strtok(cmdRecv, " ");
	char * message = strtok(NULL, "");
	int cmd = strToMsg(command);
	
	switch(cmd) {
		case IDLE:
			break;
		case LOGIN:
			login(i, message);
			break;
		case LOGOUT:
			logout(i);
			break;
		case PRINT:
			Log("%s", message);
			break;
		case ERROR:
			Log("ERROR: %s", message);
			break;
		case LISTEN:
			reqSock(message);
			break;
		case RECV:
			recvf(i);
			break;
		default:
			Log("Unknown client command '%s' received from server. Exiting...", command);
			exit(-1);
	}
}

int main(int argc, char *argv[]) {
	char *line = (char *)malloc(sizeof(char) * CMD_LEN);
	timestamp = (char *)malloc(sizeof(char) * 11);
	int n;
	
	// command line arguments must follow form detailed in project outline
	if (argc < 4) {
		Log("Incorrect number of arguments. Proper usage: './client [Server IP Address] [Server Port] [Input Script]'");
		return -1;
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
	int conn = connect(sock, (const struct sockaddr *) &serverAddr, sizeof(serverAddr));
	if (sock == -1 || conn == -1) {
		Log("ERROR: Failed to connect to the server. Closing...");
		return -1;
	}
	
	// Set the socket with non-blocking IO
	SetNonBlockIO(sock);
	
	// Let the user know they have connected
	Log("INFO: You have successfully connected to GopherChat. The time is %s.", getTimestamp());

	// Initialize global variables and socket info structs
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
		Log("Unable to open file '%s'.", argv[3]);
		return -1;
	}
	
	// Read the first line of the script and find the command type
	if(getline(&line, &len, input) == -1) {
		Log("ERROR: Initial getline failed. Closing connection.");
		return -1;
	}
	sprintf(connStat[0].cmdSend, "%s", line);
	connStat[0].msg = cmdToMsg(connStat[0].cmdSend);
	
	// The main loop for carrying out nonblocking operations
	while (1) {			
		// Poll for any events happening on any open connection
		int r = poll(peers, nConns + 1, timeout);	
		// A timeout has occurred, a DELAY command has finished
		if (r == 0) {
			// Allow for writing on the socket again
			peers[0].events |= POLLWRNORM;		
			
			// Grab the next line from the script and find its command type
			memset(connStat[0].cmdSend, 0, CMD_LEN);
			if(getline(&line, &len, input) == -1) {
				Log("End of script reached, disconnecting from server...");
				break;
			}
			sprintf(connStat[0].cmdSend, "%s", line);
			connStat[0].msg = cmdToMsg(connStat[0].cmdSend);
			
			// If the next message is a SENDF or SENDF2, create a new data socket to handle transferring the file to the server
			if (connStat[0].msg == SENDF || connStat[0].msg == SENDF2) {
				if (connStat[0].loggedIn) {
					createDataSocket(connStat[0].msg, connStat[0].cmdSend);
				}
				else {
					Log("ERROR: Cannot send file, you are not logged in.");
				}
					
				// Change the command sent to the server from the message socket (socket 0 on client side) to IDLE
				memset(connStat[0].cmdSend, 0, CMD_LEN);
				sprintf(connStat[0].cmdSend, "IDLE");
				connStat[0].msg = 0;
				continue;
			}
			
			// If the next command is a DELAY, set the timeout value to whatever was requested
			if (connStat[0].msg == DELAY) {
				char* parse = strtok(line, " ");
				parse = strtok(NULL, " ");
				int msec = atoi(parse);
				timeout = msec  * 1000;
			}
			else {
				// Otherwise change timeout to -1 to poll indefinately while not in a delay
				timeout = -1;
			}
		}	
		
		// For all data sockets, check what event has occured and on which socket
		for (int i=0; i<=nConns; i++) {
			// A socket is requesting to receive data
			if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
				if (connStat[i].nCmdRecv < CMD_LEN) {
					if (Recv_NonBlocking(peers[i].fd, connStat[i].cmdRecv, CMD_LEN, &connStat[i], &peers[i]) < 0) {
						// If the connection has been closed from the server side, close the client gracefully
						if (i == 0) {
							Log("Connection lost with server, shutting down.");
							
							// Close the input file after end of file
							fclose(input);

							// After execution, allocated memory for storing lines of commands can be freed
							free(line);

							//Close socket
							close(sock);
							return 0;
						}
						RemoveConnection(i);
					}
					if (connStat[i].nRecv == CMD_LEN) {
						connStat[i].nRecv = 0;
						
						// All sockets receive commands back from the server, not messages
						if (i > 0) {
							// Any socket on the client size with i>0 is a file transfer helper
							// Parse through the command returned by the server to retrieve the filename and filesize that will be sent next
							connStat[i].nCmdRecv = CMD_LEN;
							char * filesize = strtok(connStat[i].cmdRecv, " ");
							filesize = strtok(NULL, " ");
							char * filename = strtok(NULL, "");
							sprintf(connStat[i].filename, "%s", filename);
							connStat[i].filesize = atoi(filesize);
							
							// Allocate memory for the file being sent
							connStat[i].file = (char *)malloc(sizeof(char) * connStat[i].filesize);
							memset(connStat[i].file, 0, connStat[i].filesize);
						}
						
						// Act on the command received from the server
						protocol(connStat[i].cmdRecv, i);
						
						// If the input script has finished, and the socket is not a file helper, go to the end to close the client gracefully
						if (eof && !i) {
							// Close the input file after end of file
							fclose(input);

							// After execution, allocated memory for storing lines of commands can be freed
							free(line);

							//Close socket
							close(sock);
							return 0;
						}
					}
				}
				
				// Act based on the command received from the server
				if (connStat[i].nCmdRecv == CMD_LEN) {
					protocol(connStat[i].cmdRecv, i);
				}
			}
			
			// A socket is requesting to send data
			if (peers[i].revents & POLLWRNORM) {
				// The command socket (socket 0) will only ever send commands
				if (connStat[i].nSent < CMD_LEN && (i == 0)) {
					if (Send_NonBlocking(sock, connStat[i].cmdSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
						if (i == 0) {
							Log("Connection lost with server, shutting down.");
							
							// Close the input file after end of file
							fclose(input);

							// After execution, allocated memory for storing lines of commands can be freed
							free(line);

							//Close socket
							close(sock);
							return 0;
						}
						RemoveConnection(i);
					}
					
					if (connStat[i].nSent == CMD_LEN) {
						connStat[i].nSent = 0;	
						
						// Allow for writing again on the socket
						peers[i].events |= POLLWRNORM;
						
						// Grab the next line from the script and find its command type
						memset(connStat[i].cmdSend, 0, CMD_LEN);
						if(getline(&line, &len, input) == -1) {
							Log("End of script reached, disconnecting from server...");
							eof = 1;
						}
						sprintf(connStat[i].cmdSend, "%s", line);
						connStat[i].msg = cmdToMsg(connStat[i].cmdSend);
						
						// If the next message is a SENDF or SENDF2, create a new data socket to handle transferring the file to the server
						if (connStat[0].msg == SENDF || connStat[0].msg == SENDF2) {
							if (connStat[i].loggedIn) {
								createDataSocket(connStat[0].msg, connStat[0].cmdSend);
							}
							else {
								Log("ERROR: Cannot send file, you are not logged in.");
							}
					
							// Change the command sent to the server from the message socket (socket 0 on client side) to IDLE
							memset(connStat[0].cmdSend, 0, CMD_LEN);
							sprintf(connStat[0].cmdSend, "IDLE");
							connStat[0].msg = 0;
							continue;
						}
						
						// If the next message is a DELAY, set the timeout to the requested value
						if (connStat[i].msg == DELAY) {
							peers[i].events &= ~POLLWRNORM;
							
							char* parse = strtok(line, " ");
							parse = strtok(NULL, " ");
							int msec = atoi(parse);
							timeout = msec  * 1000;
						}
						else {
							// Otherwise set timeout to -1 to poll indefinitely
							timeout = -1;
						}
					}
				}
				
				// The data sockets will send both a command (RECVF/RECVF2) and a file
				else if (i > 0) {
					// Send command
					if (connStat[i].nStatSent < CMD_LEN) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].cmdSend, CMD_LEN, &connStat[i], &peers[i]) < 0) {
							Log("Command sent incorrectly.");
							RemoveConnection(i);
						}
						if (connStat[i].nSent == CMD_LEN) {
							connStat[i].nStatSent = CMD_LEN;
							connStat[i].nSent = 0;
						}
					}
					
					// Send file
					if (connStat[i].nStatSent == CMD_LEN && connStat[i].nSent < connStat[i].filesize) {
						if (Send_NonBlocking(peers[i].fd, connStat[i].file, connStat[i].filesize, &connStat[i], &peers[i]) < 0) {
							Log("File sent incorrectly.");
							RemoveConnection(i);
						}
						if (connStat[i].nSent == connStat[i].filesize) {
							// File has been sent, it is safe to free memory used by file
							free(connStat[i].file);
							connStat[i].nStatSent = 0;
							connStat[i].nSent = 0;
						}
					}
				}
			}
		}
	}
	
	// This should never be reached if the client shuts down correctly
	return -1;
}
