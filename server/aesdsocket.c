/*
 *  Author      : Vignesh Vadivel
 *  email       : viva9969@colorado.edu
 *  Course      : Advanced Embedded Software Development
 *  Code        : ECEN 5713
 *  University  : University of Colorado at Boulder
 *  File        : aesdsocket.c
 *  Date        : 23-Feb-2023
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
#include <sys/stat.h>
#include <sys/time.h>

/****************************** STANDARD C LIBRARIES ****************************/
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

/************************** LIBRARIES FROM THIS PROJECT ************************/
#include "queue.h"

/************************************* MACROS ***********************************/
#define PORT_FOR_SOCKET     "9000"
#define FILE_PERMISSIONS    0744
#define BACK_LOG            10
#define SOCKET_PATH         "/var/tmp/aesdsocketdata"
#define BUFFER_LENGTH       100
#define STATUS_FAILURE      -1
#define STATUS_SUCCESS       0
#define NUMBER_OF_ARGUMENTS  2
#define TIMESTAMP_LEN        256
#define SLEEP_TIME_SEC       10


/******************************** GLOBAL VARIABLES ******************************/
int sockFd, fileFd_W_R, clientFd;
bool fileOpenFlag = false;
bool daemonMode = false;
bool logOpenFlag = false;
bool socketOpenFlag = false;
bool clientFdOpenFlag = false;
bool signalCaught = false;
pthread_mutex_t mutexLock = PTHREAD_MUTEX_INITIALIZER;
int bytesToBeWritten = 0;
SLIST_HEAD(slisthead, slist_data_s) head;

/***************************** STRUCT FOR LINKED LIST ***************************/
typedef struct{
  pthread_t tid;
  bool threadComplete;
  int clientFd;
  char ipString[INET6_ADDRSTRLEN];
} thread_param_t;

typedef struct slist_data_s
{
    thread_param_t threadParam;
    SLIST_ENTRY(slist_data_s) entries;
} slist_data_t;

/******************************** FUNCTION PROTOTYPES ******************************/
void myCustomExit();
void *getAddress(struct sockaddr *sadd);
void mySignalHandler(int signo);
int mySocketServer();
void exitThread(thread_param_t*, char*);

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
 * Function that would be ran as a separate thread to log time stamp values
 * Parameters  : None  => This thread function has no input parameters
 * Return Type : void* => Thread functoin returns NULL pointer
 *
 */
void *logTimeStamp() {
  time_t currentTime;
  struct tm *timeInfo;
  int returnStatus;
  char timestamp[TIMESTAMP_LEN];
  sleep(SLEEP_TIME_SEC);
  
  while (!(signalCaught)) {                                                                        // Log time stamp values till SIGTERM or SIGINT is caught //
    time(&currentTime);
    timeInfo = localtime(&currentTime);                                                            // Get local time //
    strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %T %z\n", timeInfo);            // Required time stamp format //
    returnStatus = pthread_mutex_lock(&mutexLock);                                                 // Mutex lock before writing into file //
    if(returnStatus != STATUS_SUCCESS){
      syslog(LOG_ERR, "Mutex lock failed \r\n");
    }
    lseek(fileFd_W_R, bytesToBeWritten, SEEK_SET);                                                 // Set the cursor position //
    bytesToBeWritten += write(fileFd_W_R, timestamp, strlen(timestamp));                           // Update number of bytes written //
    returnStatus = pthread_mutex_unlock(&mutexLock);                                               // Mutex unlock after write //
    if(returnStatus != STATUS_SUCCESS){
      syslog(LOG_ERR, "Mutex Unlock failed \r\n");
    }
    sleep(SLEEP_TIME_SEC);                                                                         // Sleep for 10 seconds //
  }
  return NULL;
}


/*
 * Function to exit from a thread
 * Parameters  : 1. thread_param_t* => Struct pointer which has all the thread info 
 *               2. char* => Pointer to the overall buffer to free(if needed)
 * Return Type : void => Function returns nothing
 *
 */
void exitThread(thread_param_t* threadParam, char* recPacket){
  if(recPacket != NULL){
    free(recPacket);
    recPacket = NULL;
  }
  syslog(LOG_INFO, "Closed connection from %s\n", threadParam->ipString);
  threadParam->threadComplete = true;
  close(threadParam->clientFd);
}


/*
 * Function which would be executed for different threads
 * Parameters  : void* =>
 * Return Type : void* => Function returns NULL pointer
 *
 */
void *threadFunc(void* threadArg){
  char recPacket[BUFFER_LENGTH];
  char* recBuffer = NULL;
  char* trsBuffer = NULL;
  int bytesPerPacket;
  int32_t bytesRcvd, noOfBytesinBuffer = 0;
  int numBufFragments = 1;
  int returnStatus;

  thread_param_t* param = (thread_param_t*) threadArg;
  recBuffer = (char*) malloc(BUFFER_LENGTH*sizeof(char)*numBufFragments);                          // Allocate overall buffer //
  if(recBuffer == NULL){
    syslog(LOG_ERR, "Malloc failed \r\n");
    return NULL;
  }
  while(((bytesRcvd = recv(param->clientFd, recPacket, BUFFER_LENGTH, 0)) > 0) && (!signalCaught)){  // Receive data over socket till it is available //
    if((numBufFragments*BUFFER_LENGTH) - noOfBytesinBuffer < bytesRcvd){                           // Check if the buffer size has to be increased //
      recBuffer = (char*)realloc(recBuffer, (++numBufFragments * BUFFER_LENGTH));                  // Realloc buffer //
      if(recBuffer == NULL){
        syslog(LOG_ERR, "realloc failed \r\n");
        exitThread(param, recBuffer);
        return NULL;
      }
    }
    memcpy(noOfBytesinBuffer+recBuffer, recPacket, bytesRcvd);                                     // Copy data to the overall buffer //
    noOfBytesinBuffer += bytesRcvd;
    bool newLine = false;
    int ind;
    for (ind=0; ind<noOfBytesinBuffer; ind++){
      if (recBuffer[ind] == '\n'){                                                                 // Check for new Line input //
        newLine = true;
        break;
      }
    }
    if (newLine){                                                                                  // New line exists //
      int bytesChanged = ind + 1;
      returnStatus = pthread_mutex_lock(&mutexLock);                                               // Mutex lock before write //
      if(returnStatus != STATUS_SUCCESS){
        syslog(LOG_ERR, "Mutex Lock failed \r\n");
        exitThread(param, recBuffer);
        return NULL;
      }
      bytesPerPacket = write(fileFd_W_R, recBuffer, bytesChanged);                                 // Write the data to file Descriptor //
      if(bytesPerPacket == STATUS_FAILURE){
        syslog(LOG_ERR, "File write system call failed \r\n");
        returnStatus = pthread_mutex_unlock(&mutexLock);                                           // Unlock Mutex if the write operation failed //
        exitThread(param, recBuffer);
        return NULL;
      }
      else{
        bytesToBeWritten += bytesPerPacket;
        noOfBytesinBuffer -= (ind + 1);
        bytesChanged = bytesToBeWritten;
        trsBuffer = (char*)malloc(bytesChanged);                                                   // Allocate memory to store the read data //
        lseek(fileFd_W_R, 0, SEEK_SET);                                                            // Set cursor to the begining of the descriptor //
        int bytesToSend = read(fileFd_W_R, trsBuffer, bytesChanged);                               // Read the data back again from the descriptor //
        if(bytesToSend == STATUS_FAILURE){
          syslog(LOG_ERR, "Cannot read from file \r\n");
          returnStatus = pthread_mutex_unlock(&mutexLock);                                         // Unlock mutex if the read operation failed //
          exitThread(param, recBuffer);
          return NULL;
        }
        else{
          ssize_t bytesSent = send(clientFd, trsBuffer, bytesToSend, 0);                           // Send data over socket if the read is successful //
          if(bytesSent == STATUS_FAILURE){
            syslog(LOG_ERR, "Send failed \r\n");
            returnStatus = pthread_mutex_unlock(&mutexLock);                                       // Unlock mutex if the send operation failed //
            exitThread(param, recBuffer);
            return NULL;
          }
          else if (bytesSent == bytesToSend){
            syslog(LOG_INFO, "Data sent properly \r\n");
          }
          else{
            syslog(LOG_ERR, "Requested Data is %d, but data sent back is only %zd \r\n",bytesToSend, bytesSent);
          }
          free(trsBuffer);                                                                         // Free the transmit buffer //
          returnStatus = pthread_mutex_unlock(&mutexLock);                                         // Unlock Mutex after successful completion //
          if(returnStatus != STATUS_SUCCESS){
            syslog(LOG_ERR, "Mutex Unlock failed \r\n");
            exitThread(param, recBuffer);
            return NULL;
          }
        }
      }
    }
  }
  exitThread(param, recBuffer);
  return NULL;
}

/*
 * Function to initiate socket communication
 * Parameters  : None => Functions accept no arguments
 * Return Type : int  => Returns 0 on success
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
  slist_data_t *tNode = NULL;
  SLIST_INIT(&head);

  /******************** ACCEPT CONNECTION TILL SIGNAL CAUGHT *******************/
  while(!signalCaught){                                                                            // Execute till SIGTERM or SIGINT //
    if(signalCaught){
      break;
    }
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
    
    tNode = malloc(sizeof(slist_data_t));                                                          // Create a Node for one thread //
    tNode->threadParam.threadComplete = false;                                                     // Thread complete is false //
    tNode->threadParam.clientFd = clientFd;                                                        // Store client descriptor //
    memcpy(tNode->threadParam.ipString, ipString, INET6_ADDRSTRLEN);                               // Encapsulate IP-String //
    returnStatus = pthread_create(&tNode -> threadParam.tid, NULL, threadFunc, (&(tNode -> threadParam)));
    if(returnStatus == STATUS_FAILURE){
      syslog(LOG_ERR, "Thread creation failed \r\n");
    }

    SLIST_INSERT_HEAD(&head, tNode, entries);                                                      // Insert thread into the head //
    slist_data_t *t_node_temp = NULL;

    SLIST_FOREACH_SAFE(tNode, &head, entries, t_node_temp){
      if(tNode -> threadParam.threadComplete){                                                     // Check if the thread is completed or not //
        if((returnStatus = pthread_join(tNode -> threadParam.tid, NULL)) != 0){                    // Join the thread //
          syslog(LOG_ERR, "Thread join failed \r\n");
        }
        close(tNode->threadParam.clientFd);                                                        // Close corresponding descriptor //
        SLIST_REMOVE(&head, tNode, slist_data_s, entries);                                         // Remove the node //
        free(tNode);                                                                               // Free the node //
      }
    }
  }
  close(sockFd);                                                                                   // Close the socket //
  socketOpenFlag = false;                                                                          // Update flag //
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
    unlink(SOCKET_PATH);                                                                           // Remove temp file from file system //
  }

  int returnStatus;
  slist_data_t *tNode, *t_node_temp;
  SLIST_FOREACH_SAFE(tNode, &head, entries, t_node_temp){
    if(tNode->threadParam.threadComplete){                                                         // Check if thread complete //
      if((returnStatus = pthread_join(tNode->threadParam.tid, NULL)) != 0){                        // Join the thread //
        syslog(LOG_ERR, "Thread Join failed \r\n");
        exit(EXIT_FAILURE);
      }
      close(tNode->threadParam.clientFd);                                                          // Close client descriptor for that thread //
      SLIST_REMOVE(&head, tNode, slist_data_s, entries);                                           // Remove Node //
      free(tNode);                                                                                 // Free Node //
    }
  }
  returnStatus = pthread_mutex_destroy(&mutexLock);                                                // Destroy mutex lock //
  if(returnStatus != STATUS_SUCCESS){
    syslog(LOG_ERR, "Mutex lock destroy failed \r\n");	
    exit(EXIT_FAILURE);
  }
}


/*
 * Function to handle external signals
 * Parameters  : int => Signal source
 * Return Type : void => Function returns nothing
 *
 */
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
  
  pthread_t time_thread;
  pthread_create(&time_thread, NULL, logTimeStamp, NULL);                                          // Run time stamp in a separate thread //
  int retVal;
  retVal = mySocketServer();                                                                       // Returns zero on success //
  myCustomExit();
  return retVal;
}
