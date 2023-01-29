#include <syslog.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char* argv[]){
  if (argc!=3){
    openlog(NULL, 0, LOG_USER);
    syslog(LOG_ERR, "Invalid Number of Arguments: %d\n", argc);
    closelog();
    return 1;
  }
  
  int fp = open(argv[1], O_CREAT | O_WRONLY , S_IRWXU | S_IRWXG | S_IRWXO);
  if (fp != -1){
    int i = strlen(argv[2]);
    int wr_status = write(fp, argv[2], i);
      openlog(NULL, 0, LOG_USER);
    if (wr_status==-1)
      syslog(LOG_ERR, "Write Operation failed with return -1\n\r");
    else if (wr_status < i)
      syslog(LOG_ERR, "Not all bytes are written to the file W - \n\r");
    else
      syslog(LOG_DEBUG, "Write Operation is Successful \n\r");
    closelog();
  }
  else{
    openlog(NULL, 0, LOG_USER);
    syslog(LOG_ERR, "File Descriptor failed with return -1\n\r");
  }
  return 0;
}
  

