#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "error.h"
#include "ssh.h"
#include "pass.h"
int main(int argc,char argv[])
{

    ssh_session my_ssh;
    int port;
    int verbosity =SSH_LOG_PROTOCOL;
    char * password;
    if(argc < 2)
    {
             port = 22;
    }
    else
    {
        port=argv[2];
    }



    if((my_ssh=ssh_new())!=NULL)
    {
       fprintf(stderr,"--Error opening ssh session--:%s",strerror(errno));
       exit(-1);
    }
    printf("--SSH Session created--");

    ec_ssh_options(ssh_options_set(my_ssh,SSH_OPTIONS_HOST,"localhost"),my_ssh);
    ec_ssh_options(ssh_options_set(my_ssh,SSH_OPTIONS_LOG_VERBOSITY,&verbosity),my_ssh);
    ec_ssh_options(ssh_options_set(my_ssh,SSH_OPTIONS_PORT,&port),my_ssh);

    if((ssh_connect(my_ssh))!=SSH_OK){
        fprintf(stderr,"Error connecting to localhost:%s\n",ssh_get_error(my_ssh));
        exit(-1);
    }

    verify_knownhost(my_ssh);
    if((test_auth_methods(my_ssh)) != SSH_AUTH_SUCCESS){
        fprintf("Error Authenticating:%s",ssh_get_error(my_ssh));
        exit (-1);
    }

    display_banner(my_ssh);

    show_remote_processes(my_ssh);

    ssh_disconnect(my_ssh);
    ssh_free(my_ssh);


}
