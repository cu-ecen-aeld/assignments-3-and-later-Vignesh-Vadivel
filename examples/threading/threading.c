#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
#define MILLISEC_TO_MICROSEC  1000
void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    thread_func_args->thread_complete_success = false;                                  // Initially success is false //
    if (!(usleep((thread_func_args->wait_to_obtain_ms)*MILLISEC_TO_MICROSEC) == 0)){    // Usleep error - Cannot sleep //
        ERROR_LOG("Usleep failed before Mutex lock \n\r");
        return thread_param;
    }
    if (!(pthread_mutex_lock(thread_func_args->myMutexLock) == 0)){                     // Obtain mutex lock //
        ERROR_LOG("Cannot obtain mutex lock \n\r");
        return thread_param;
    }
    if (!(usleep((thread_func_args->wait_to_release_ms)*MILLISEC_TO_MICROSEC) == 0)){   // Usleep error - Cannot sleep //
        ERROR_LOG("Usleep failed before Mutex lock release \n\r");
        return thread_param;
    }
    if (!(pthread_mutex_unlock(thread_func_args->myMutexLock) == 0)){                   // Release mutex lock //
        ERROR_LOG("Cannot release mutex lock \n\r");
        return thread_param;
    }
    thread_func_args->thread_complete_success = true;                                   // Successful completion //
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data* myData = (struct thread_data*)malloc(sizeof(struct thread_data));
    myData->wait_to_obtain_ms = wait_to_obtain_ms;
    myData->wait_to_release_ms = wait_to_release_ms;
    myData->myMutexLock = mutex;
    int ret = pthread_create(thread, NULL, threadfunc, (void *)myData);
    if (ret == 0){                                                              // Thread creation is successful //
        return true;
    }
    else{                                                                       // Thread creation is unsuccessful //
        free(myData);
        ERROR_LOG("Thread creation failed  \n\r");
    }
    return false;
}

