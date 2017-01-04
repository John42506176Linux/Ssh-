#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <libssh/libssh.h>
#include <string.h>


int ec(int check,char * function ){

        if(!(strcmp("getaddrinfo",function))){

            if(check!=0){
                fprintf(stderr,"%s:%s\n",function,gai_strerror(check));

                exit(1);
             }
        }


        else{
            if(check==-1){

                fprintf(stderr,"%s:%s\n",function,strerror(errno));

                exit(1);
            }


        }
        return 1;
    }

void eccomp(pcap_t handle,int check){
  if(check == -1){
    pcap_perror("pcap_compile:");
  }
}
void ecnet(int check,char *function ,char * errbuff){
  if(check ==-1){
    fprintf(stderr,"%s:%s",function,errbuff);
    exit(1);
  }
}
void ecpcap(char * device,char * function,char * errbuff){

  if(device == NULL){
    fprintf(stderr,"%s:%s",function,errbuff);
    exit (1);
  }
}
void ecfile(FILE *fp,char *function){
 if(fp==NULL){
                fprintf(stderr,"%s:%s\n",function,strerror(errno));
                exit(1);
            }

}

void *ec_malloc( unsigned int bytes){
        void *pointer;
        if ((pointer=malloc(bytes))==NULL&&bytes!=0){
            fprintf(stderr,"Out of memory\n");
            exit(1);
        }
        return pointer;

}

void ec_ssh_options (int check,ssh_session session){

    if(check<0){
         fprintf(stderr,"ssh_options_set:%s\n",ssh_get_error(session));
         exit(-1);
    }
}
