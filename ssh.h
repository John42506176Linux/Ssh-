#include <libssh/libssh.h>
#include <stdio.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "pass.h"
void ssh_channel_clee(ssh_channel channel){
    ssh_channel_free(channel);
    ssh_channel_close(channel);
}
int verify_knowhost(ssh_session session)
{
    int state,hlen;
    unsigned char *hash= NULL;



    if((hlen=ssh_get_pubkey_hash(session,&hash)))
    return -1;

    switch((state=ssh_is_server_known(session)))
    {
        case SSH_SERVER_KNOWN_OK:
        break;

        case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr,"Host key for server changed: it is now :%s\n",ssh_print_hexa("Public key hash",hash,hlen));
        fprintf(stderr,"In the the interest of security we must stop the connection\n");
        free(hash);
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);

        case SSH_SERVER_FOUND_OTHER:
        fprintf(stderr,"The host key for this server was not found but another type of key exist\.n");
        fprintf(stderr,"An attacker might change the default server to trick the client to beleive it does not exist. Registered as malicious activity. Stopping connection\n");
        free(hash);
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);

        case SSH_FILE_NOT_FOUND:
            fprintf(stderr,"Could not find know host file.\n");
            fprintf(stderr,"If you accept the host key the file will automatically be created.\n");
        case SSH_SERVER_NOT_KNOWN:
            char *hexa;
            hexa =ssh_get_hexa(hash,hlen);
            char buf[10];
            fprintf(stderr,"The server is unknown do you trust the host key?\n");
            fprintf(stderr,"Publuc key hash:%s\n",hexa);
            free(hexa);
            if(fgets(buf,sizeof buf,stdin) == NULL)
            {
                free(hash);
                ssh_disconnect(session);
                ssh_free(session);
                exit(-1);
            }
            if(strncasecmp(buf,"yes",3) != 0)
            {
                free (hash);
                ssh_disconnect(session);
                ssh_free(session);
                exit(-1);
            }
            if(ssh_write_knownhost(session) < 0)
            {
                fprintf(stderr,"Error:%s\n",strerror(errno));
                free(hash);
                ssh_disconnect(session);
                ssh_free(session);
                exit(-1);
            }
        break;
        case SSH_SERVER_ERROR:
            fprintf(stderr,"Error:%s",ssh_get_error(session));
            free(hash);
            ssh_disconnect(session);
            ssh_free(session);
            exit(-1);
    }
    free(hash);
    return 0;
}
int auth_pubkey_auto(ssh_session session)
{
    if((int rc =ssh_userauth_publickey_auto(session,NULL)== SSH_AUTH_ERROR)
    {
        fprintf(stderr,"Authentication error:%s",ssh_get_error(session));
        return SSH_AUTH_ERROR;
    }
    return rc;

}

int show_remote_processes(ssh_session session){
    ssh_channel channel;
    char buffer[256];
    int rc_nbytes;

    if((channel =ssh_channel_new(session))==NULL)
    return SSH_ERROR;

    if((ssh_channel_open_session(channel)) != SSH_OK)
    {
        ssh_channel_free(channel);
    }
    if((rc_nbytes=ssh_channel_request_exec(channel,"ps aux")) != SSH_OK)
    {
        ssh_channel_clee(channel);
        return rc_nbytes;
    }
    while((rc/nbytes =ssh_channel_read(channel,buffer,sizeof(buffer),0)) > 0)
    {
        if(write(1,buffer,rc_nbytes) != (unsigned int)rc_nybtes)
        {
            ssh_channel_clee(channel);
        }
        rc_nbytes =ssh_channel_read(channel,buffer,sizeof(buffer),0);
    }
    if(rc_nbytes < 0)
    {

        ssh_channel_clee(channel);
        return SSH_ERROR;
    }
    ssh_channel_send_eof(channel);
    ssh_channel_clee(channel);

    return SSH_OK;
}
void auth_auto_pass(ssh_session my_ssh){
        int rc;

        if((rc =ssh_userauth_password(my_ssh,NULL,edgetpass("Enter your password:")))!= SSH_AUTH_SUCCESSS){
            fprintf("Error authenticating password: %s \n",ssh_get_error(my_ssh));
            ssh_clee(my_ssh);
            exit(-1);
        }
        return rc;
}
int auth_kbdint(ssh_session session)
{
    int rc;

    rc= ssh_userauth_kbdint(session,NULL,NULL);

    while(rc == SSH_AUTH_INFO)
    {
        const char *name,*instruction;
        int nprompts,iprompt;

        if(strlen(name= ssh_userauth_kbdint_getname(session)) > 0)
            printf("%s\n",name);
        if(strlen(instruction =ssh_userauth_kbdint_getname(session))>0){
            printf("%s/n",instruction);
        }
        for(iprompt =0;iprompt <(nprompts = ssh_userauth_kbdint_getnprompts(session));iprompt++)
        {
            const char * prompt;
            char echo;
            prompt =ssh_userauth_kbdint_getprompt(session,iprompt,&echo);
            if(echo){
                char buffer[128],*ptr;

                printf("%s",prompt);
                if(fgets(buffer,sizeof(buffer),stdin) == NULL)
                    return SSH_AUTH_ERROR;
                buffer[sizeof(buffer)-1] = '\0';
                if((ptr=strchr(buffer,'\n'))!=NULL)
                    *ptr = '\0';
                if(ssh_userauth_kbdint_setanswer(session,iprompt,buffer) < 0)
                    return SSH_AUTH_ERROR;
                memset(buffer,0,strlen(buffer));

            }
            else
            {
                 char *ptr;
                 ptr = edgetpass(prompt);
                 if(ssh_userauth_kbdint_setanswer(session,iprompt,ptr) < 0)
                 return SSH_AUTH_ERROR;
            }
        }
        rc =ssh_userauth_kbdint(session,NULL,NULL);
    }
    return rc;
}
int auth_none(ssh_session session)
{
    return(ssh_userauth_none(session,NULL));
}
int test_auth_methods(ssh_session session)
{
    int method;
    if((ssh_userauth_none(session,NULL)) != SSH_AUTH_SUCCESS)
    {
        if((method=ssh_userauth_list(session,NULL)) & SSH_AUTH_METHOD_PUBLICKEY)
        {
            if((auth_pubkey_auto(session) == SSH_AUTH_SUCCESS) return SSH_AUTH_SUCCESS;
        }
        if(method & SSH_AUTH_METHOD_INTERACTIVE)
        {
            if((auth_kbdint(session)) == SSH_AUTH_SUCCESS) return SSH_AUTH_SUCCESS;
        }
        if(method & SSH_AUTH_METHOD_PASSWORD)
        {
            if(auth_auto_pass(session) == SSH_AUTH_SUCCESS) return SSH_AUTH_SUCCESS;
        }
        return SSH_AUTH_ERROR;
    }

    else{
        return SSH_AUTH_SUCCESS;
    }
}
int display_banner(ssh_session session){
    int rc;
    char * banner;

    if(rc == SSH_AUTH_ERROR)
        return rc;
    banner = ssh_get_issue_banner(session,NULL);
    if(banner)
    {
        printf("%s\n",banner);
        free(banner);
    }

    return rc;
}
int shell_session(ssh_session session)
{
    ssh_channel channel;
    int rcl
     if((channel =ssh_channel_new(session)) == NULL)
        return SSH_ERROR;
    if((rc=ssh_channel_open_session(channel)) != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int interact_shell_session(ssh_channel channel)
{
    int rc;
    ssh_channel x11channel;
    char buffer[256];
    int nbytes,nwritten;
    struct termios t_in;
    tcgetattr(0,&t_in);
    cfmakeraw(&t_in);


    if((rc = ssh_channel_request_pty(channel)) != SSH_OK ) return rc;

    if((rc= ssh_channel_change_pty_size(channel,80,24))!= SSH_OK) return rc;

    if((x11channel= ssh_channel_accept_x11(channel,100000))== NULL)
    {
        return SSH_ERROR;
    }
    if((rc=ssh_channel_request_x11(channel,0,NULL,NULL,0))!= SSH_OK) return rc;
    if((rc = ssh_channel_request_shell(channel) != SSH_OK) return rc;


    while(ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel))
    {
        struct timeval timeout;
        ssh_channel in_channels[2],out_channels[2];
        fd_set fds;
        int maxfd;
        timeout.tv_sec =30;
        timeout.u_ec= 0;
        in_channels[0] = channel;
        in_channels[1] = NULL;
        FD_ZERO(&fds);
        FD_SET(0,&fds);
        FD_SET(ssh_get_fd(session),&fds);
        maxfd = ssh_get_fd(session)+1;

        ssh_select(in_channels,out_channels,maxfd,&fds,&timeout);

        if(out_channels[0] != NULL)
        {
            nbytes = ssh_channel_read(channel,buffer,sizeof(buffer),0);
            if(nbytes < 0)
            return SSH_ERROR;
            if(nbytes > 0)
            {
                nwritten = write(1,buffer,nbytes);
            if(nwritten != nbytes) return SSH_ERROR;
            }

        }


        if(FD_ISSET(0,&fds))
        {
            nbytes = read(0,buffer,sizeof(buffer));
            if(nbytes < 0)
             return SSH_ERROR;
            if(nbytes > 0)
            {
                nwritten = ssh_channel_write(channel,buffer,nbytes);
                if(nwritten != nbytes) return SSH_ERROR;
            }
        }

    }
    cfmakerawreverse(&t_in);
    return rc;

}
int kbhit()
{
    struct timeval tv = {0L,0L};
    fdset fds;

    FD_ZERO(&fds);
    FD_SET(0,fds);

    return select(1,&fds,NULL,NULL,&tv);
}
int show_remote_files(ssh_session session)
{
    ssh_channel channel;
    int rc;

    if((channel = ssh_channel_new(session)) == NULL) return SSH_ERROR;

    if((rc=ssh_channel_open_session(channel))!= SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    if((ssh_channel_request_exec(channel,"ls -l")) != SSH_OK){
        ssh_channel_clee(channel);
        return rc;
    }

    char buffer[256];
    int nbytes;

    nbytes = ssh_channel_read(channel,buffer,sizeof(buffer),0);
    while(nbytes > 0)
    {
        if(fwrite(buffer,1,nbytes,stdout) != nbytes)
        {
            ssh_channel_clee(channel);
            return SSH_ERROR;
        }
        nbytes =ssh_channel_read(channel,buffer,sizeof(buffer),0);

    }
    if(nbytes < 0)
    {
        ssh_channel_clee(channel);
        return SSH_ERROR;
    }
    ssh_channel_send_eof(channel);
    ssh_channel_clee(channel);
    return SSH_OK;
}
