/*
 *  Author      : Vignesh Vadivel
 *  email       : viva9969@colorado.edu
 *  Course      : Advanced Embedded Software Development
 *  Code        : ECEN 5713
 *  University  : University of Colorado at Boulder
 *  File        : aesdsocket.c
 *
 *
 */

/******************************** SYSTEM LIBRARIES ******************************/
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
#include <syslog.h>

/****************************** STANDARD C LIBRARIES ****************************/
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/************************************* MACROS ***********************************/
#define PORT_FOR_SOCKET     "9000"
#define FILE_PERMISSIONS    0744
#define BACK_LOG            10
#define SOCKET_PATH         "/var/tmp/aesdsocketdata"
#define BUFFER_LENGTH       100
#define STATUS_FAILURE      -1
#define NUMBER_OF_ARGUMENTS  2

/******************************** GLOBAL VARIABLES ******************************/
int sockFd, fileFd_W_R, clientFd;
bool fileOpenFlag = false;
bool daemonMode = false;
bool logOpenFlag = false;
bool socketOpenFlag = false;
bool clientFdOpenFlag = false;
bool signalCaught = false;

/******************************** FUNCTION PROTOTYPES ******************************/
void myCustomExit();
void *getAddress(struct sockaddr *sadd);
void mySignalHandler(int signo);
int mySocketServer();

/***************************** FUNCTION DEFINITIONS ******************************/
/*
 * Function to return socket address either IPV4 or IPV6
 * Input : struct sockaddr*  => Pointer to the sockaddr struct
 * Return : void => Function returns nothing
 *
 */
void *getAddress(struct sockaddr *sadd){
  if (sadd->sa_family == AF_INET6)                                                                 // For IPv6 //
    return &(((struct sockaddr_in6*)sadd)->sin6_addr);
  return &(((struct sockaddr_in*)sadd)->sin_addr);                                                 // For IPv4 //
}

/*
 * Function which handles all socket communication
 * Input  : None
 * Return : int => Function returns 0 if socket communication is successful
 *
 */
int mySocketServer(){
  /**************************** LISTEN TO A SOCKET ***************************/
  int returnStatus = listen(sockFd, BACK_LOG);
  if(returnStatus == STATUS_FAILURE){
    syslog(LOG_ERR, "Listen Failed \r\n");
    return EXIT_FAILURE;
  }
  else{
    syslog(LOG_INFO, "Listen is successfull \r\n");
  }
  
  /***************************** SOCKET VARIABLES ****************************/
  struct sockaddr peerAddr;
  socklen_t peerAddrLen = sizeof(peerAddr);
  int32_t bytesRcvd, noOfBytesinBuffer = 0;
  uint32_t numBufFragments = 1;
  int32_t bytesPerPacket;
  uint32_t bytesToBeWritten = 0;
  char recPacket[BUFFER_LENGTH];
  char* recBuffer = NULL;
  char* trsBuffer = NULL;
  
  /******************** ACCEPT CONNECTION TILL SIGNAL CAUGHT *******************/
  while(!signalCaught){                                                                            // Execute till SIGTERM or SIGINT //
    char ipString[INET6_ADDRSTRLEN];
    clientFd = accept(sockFd, (struct sockaddr*)&peerAddr, &peerAddrLen);                          // Accept connection //
    if(clientFd == STATUS_FAILURE){
      syslog(LOG_ERR, "Cannot accept connection \r\n");
      return EXIT_FAILURE;
    }
    else{
      inet_ntop(peerAddr.sa_family, getAddress((struct sockaddr*)&peerAddr), ipString, sizeof(ipString));
      syslog(LOG_INFO, "Connection accepted - %s \r\n", ipString);                                 // Print IP address //
      clientFdOpenFlag = true;
    }
    
    recBuffer = (char*) malloc(BUFFER_LENGTH*sizeof(char)*numBufFragments);                        // Allocate overall buffer //
    if(recBuffer == NULL){
      syslog(LOG_ERR, "Malloc failed \r\n");
      return EXIT_FAILURE;
    }

    while((bytesRcvd = recv(clientFd, recPacket, BUFFER_LENGTH, 0)) > 0){                          // Receive data over socket till it is available //
      if((numBufFragments*BUFFER_LENGTH) - noOfBytesinBuffer < bytesRcvd){                         // Check if the buffer size has to be increased //
        recBuffer = (char*)realloc(recBuffer, (++numBufFragments * BUFFER_LENGTH));                // Realloc buffer //
        if(recBuffer == NULL){
          syslog(LOG_ERR, "realloc failed \r\n");
          return EXIT_FAILURE;
        }
      }
      memcpy(noOfBytesinBuffer+recBuffer, recPacket, bytesRcvd);                                   // Copy data to the overall buffer //
      noOfBytesinBuffer += bytesRcvd;
      bool newLine = false;
      int ind;
      for (ind=0; ind<noOfBytesinBuffer; ind++){
        if (recBuffer[ind] == '\n'){                                                               // Check for new Line input //
          newLine = true;
          break;
        }
      }
      if (newLine){            
        int bytesChanged = ind + 1;
        bytesPerPacket = write(fileFd_W_R, recBuffer, bytesChanged);                               // Write the data to file Descriptor //
        if(bytesPerPacket == STATUS_FAILURE){
          syslog(LOG_ERR, "File write system call failed \r\n");
          return EXIT_FAILURE;
        }
        else if(bytesPerPacket < bytesChanged){
          syslog(LOG_ERR, "File write is incomplete \r\n");
          return EXIT_FAILURE;
        }
        else{
          bytesToBeWritten += bytesPerPacket;
          noOfBytesinBuffer -= (ind + 1);
          bytesChanged = bytesToBeWritten;
          trsBuffer = (char*)malloc(bytesChanged);                                                 // Allocate memory to store the read data //
          lseek(fileFd_W_R, 0, SEEK_SET);                                                          // Set cursor to the begining of the descriptor //
          int bytesToSend = read(fileFd_W_R, trsBuffer, bytesChanged);                             // Read the data back again from the descriptor //
          if(bytesToSend == STATUS_FAILURE){
            syslog(LOG_ERR, "Cannot read from file \r\n");
            return EXIT_FAILURE;
          }
          else{
            ssize_t bytesSent = send(clientFd, trsBuffer, bytesToSend, 0);                         // Send data over socket if the read is successful //
            if(bytesSent == STATUS_FAILURE){
              syslog(LOG_ERR, "Send failed \r\n");
              return EXIT_FAILURE;
            }
            else if (bytesSent == bytesToSend){
              syslog(LOG_INFO, "Data sent properly \r\n");
            }
            else{
              syslog(LOG_ERR, "Requested Data is %d, but data sent back is only %zd \r\n",bytesToSend, bytesSent);
            }
            free(trsBuffer);                                                                       // Free the transmit buffer //
          }
        }
      }
    }
    if(bytesRcvd == STATUS_FAILURE){
      syslog(LOG_ERR, "Error in received bytes \r\n");
      return EXIT_FAILURE;
    }
    free(recBuffer);
    inet_ntop(peerAddr.sa_family, getAddress((struct sockaddr*)&peerAddr), ipString, sizeof(ipString));
    syslog(LOG_INFO, "Connection closed - %s \r\n", ipString);
  }
  close(sockFd);
  socketOpenFlag = false;
  return 0;
}
/*
 * Function which is used to exit all the open descriptors
 * Input  : None
 * Return : void => Function returns nothing
 *
 */
void myCustomExit(){
  if(fileOpenFlag){
    close(fileFd_W_R);                                                                             // Close open file descriptor //
    fileOpenFlag = false;
  }
  if(clientFdOpenFlag){
    close(clientFd);                                                                               // Close client socket descriptor //
    clientFdOpenFlag = false;
  }  
  if(logOpenFlag){
    closelog();                                                                                    // Close Log file //
    logOpenFlag = false;
  }

  if(socketOpenFlag){
    close(sockFd);                                                                                 // Close server socket descriptor //
    socketOpenFlag = false;
  }

  if(signalCaught){
    remove(SOCKET_PATH);                                                                           // Remove temp file from file system //
  }
}

void mySignalHandler(int signo){
  bool correctSignal = (signo == SIGINT || signo == SIGTERM) ? true:false;                         // Check for correct signal //
  if(correctSignal){
    syslog(LOG_INFO, "Known Signal, quitting the process \r\n");
    signalCaught = true;
    myCustomExit();
    exit(EXIT_SUCCESS);
  }
}

int main(int argc, char* argv[])
{

  /****************************** ENABLE LOGGING ******************************/
  openlog(NULL, LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);
  logOpenFlag = true;
  syslog(LOG_INFO, "Logging Options Enabled \r\n");
  
  
  /**************************** INITIALIZE SIGNALS ***************************/
  if((signal(SIGTERM, mySignalHandler) == SIG_ERR) || (signal(SIGINT, mySignalHandler) == SIG_ERR)) {
    syslog(LOG_ERR, "Signal Initialization failed \r\n");
    exit(EXIT_FAILURE);
  }
  else{
    syslog(LOG_INFO, "Signal Initialization is successful \r\n");
  }

  /****************************** GET ADDRESS INFO ******************************/
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int returnStatus = getaddrinfo(NULL, PORT_FOR_SOCKET, &hints, &res);
  if(returnStatus == STATUS_FAILURE){
    syslog(LOG_ERR, "getaddrinfo() failed \r\n");
    myCustomExit();
    return EXIT_FAILURE;
  }
  else{
    syslog(LOG_INFO, "getaddrinfo() is successful \r\n");
  }

  /******************************** OPEN SOCKET ********************************/
  sockFd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(sockFd == STATUS_FAILURE){
    syslog(LOG_ERR, "socket() creation failed \r\n");
    myCustomExit();
    return EXIT_FAILURE;
  }
  else{
    socketOpenFlag = true;
    syslog(LOG_INFO, "socket() creation is successful \r\n");
  }

  /***************************** CHECK BIND ERRORS *****************************/
  int optVal = 1;
  returnStatus = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optVal, sizeof(optVal));
  if(returnStatus == STATUS_FAILURE) {
    syslog(LOG_ERR, "setsockopt() failed \r\n");
    myCustomExit();
    return EXIT_FAILURE;
  }
  else{
    syslog(LOG_INFO, "setsockopt() is successful \r\n");
  }

  /***************************** BIND ADDRESS *****************************/
  returnStatus = bind(sockFd, res->ai_addr, res->ai_addrlen);
  if(returnStatus == STATUS_FAILURE){
    syslog(LOG_ERR, "bind() failed \r\n");
    myCustomExit();
    return EXIT_FAILURE;
  }
  else{
    syslog(LOG_INFO, "bind() is successful \r\n");
  }

  /******************************** FREE RESULT ********************************/
  freeaddrinfo(res);
  syslog(LOG_INFO, "addrinfo is freed \r\n");
  
  /**************************** DAEMON SUPPORT CHECK ***************************/
  if((argc != NUMBER_OF_ARGUMENTS)){
    syslog(LOG_INFO, " %d arguments expected, but passed = %d\r\n", NUMBER_OF_ARGUMENTS, argc);
  }
  else{
    if(strcmp(argv[1], "-d") == 0){
      syslog(LOG_INFO, "Daemon mode\r\n");
      daemonMode = true;
    }
    else{
      syslog(LOG_ERR, "Invalid argument :- expected -d :- But %s is given \r\n", argv[1]);
      return EXIT_FAILURE;
    }
  }

  
  /**************************** OPEN FILE DESCRIPTOR ***************************/
  fileFd_W_R = open(SOCKET_PATH, O_RDWR | O_APPEND | O_CREAT, FILE_PERMISSIONS);
  if(fileFd_W_R == STATUS_FAILURE){
    syslog(LOG_ERR, "Open file descriptor failed \r\n");
    myCustomExit();
    return EXIT_FAILURE;
  }
  else{
    syslog(LOG_INFO, "File descriptor opened successfully \r\n");
  }
  

  /************************** START DAEMON IF ENABLED *************************/
  if(daemonMode){
    if((returnStatus = daemon(0, 0)) == STATUS_FAILURE){
      syslog(LOG_ERR, "Cannot start Daemon \r\n");
      myCustomExit();
      return EXIT_FAILURE;
    }
    else{
      syslog(LOG_INFO, "Daemon started successfully \r\n");
    }
  }

  /**************************** START SOCKET SERVER ***************************/
  int retVal;
  retVal = mySocketServer();                                                                       // Returns zero on success //
  myCustomExit();
  return retVal;
}

