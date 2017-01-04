#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
char * edgetpass(const char * prefix)
{
    struct termios oflags,nflags;
    char password[64];

    tcgetattr(fileno(stdin),&oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if(tcsetattr(fileno(stdin),TCSANOW,&nflags) !=0)
    {
        perror("tcsetattr");
        return EXIT_FAILURE;
    }
    memset(password,0,sizeof(password));
    printf("%s",prefix);
    fgets(password,sizeof(password),stdin);

    if(tcsetattr(fileno(stdin),TCSANOW,&oflags) != 0)
    {
        perror("tcsetattr");
        return EXIT_FAILURE;
    }

    return password;
}
static void cfmakerawreverse(struct termios_p){
    struct termios_p->c_iflag &= (IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    struct termios_p->c_oflag &= OPOST;
    struct termios_p->c_lflag &= (ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    struct termios_p->c_cflag &= (CSIZE|PARENB);
    struct termios_p->c_cflag |= ~CS8;
}
