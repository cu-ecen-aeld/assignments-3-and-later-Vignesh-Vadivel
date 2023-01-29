
/*
 *  
 *  Author     : Vignesh Vadivel
 *  email      : viva9969@colorado.edu 
 *  Course     : Advanced Embedded Software Development
 *  Assignment : 02
 * 
 */

/***************************************** HEADER_FILES *******************************************************/
#include <syslog.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

/***************************************** Main Function *******************************************************/
int main(int argc, char* argv[]){
  if (argc!=3){                                                                  // Check valid number of arguments //
    openlog(NULL, 0, LOG_USER);                                                  // Open Log file //
    syslog(LOG_ERR, "Invalid Number of Arguments: %d\n", argc);                  // Log the error message //
    closelog();                                                                  // Close log file //
    return 1;
  }
  
  int fp = open(argv[1], O_CREAT | O_WRONLY , S_IRWXU | S_IRWXG | S_IRWXO);      // Open the file to write //
  if (fp != -1){                                                                 // Check if the file pointer is valid //
    int i = strlen(argv[2]);                                                     // Calculate the total characters to be written into the file //
    int wr_status = write(fp, argv[2], i);                                       // Write into the file //
    openlog(NULL, 0, LOG_USER);                                                  // Open Log file //
    if (wr_status==-1){                                                          // Check if the write action was succesfull //
      syslog(LOG_ERR, "Write Operation failed with return -1\n\r");
      closelog();
      close(fp);                                                                 // Close file descriptor //
      return 1;
    }
    else if (wr_status < i){                                                     // Check if only partial number of bytes were written //
      syslog(LOG_ERR, "Not all bytes are written to the file W - \n\r");
      closelog();
      close(fp);                                                                 // Close file descriptor //
      return 1;
    }
    else{                                                                        // Successfull write operation //
      syslog(LOG_DEBUG, "Write Operation is Successful \n\r");
      closelog();
      close(fp);                                                                 // Close file descriptor //
    }
  }
  else{
    openlog(NULL, 0, LOG_USER);                                                  // Open Log file //
    syslog(LOG_ERR, "File Descriptor failed with return -1\n\r");                // Log error message //
    closelog();                                                                  // Close Log file //
    return 1;
  }
  return 0;
}
  

