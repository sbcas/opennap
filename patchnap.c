/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the GNU Public
   License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>

/* this program allows you to do a binary edit of the linux nap v0.9 binary
and change the metaserver which it attempts to connect to.  what i do is set
the metaserver to 127.0.0.1 and use the metaserver binary from opennap to
direct the client to the opennap server */

/* WARNING! I SUGGEST YOU MAKE A BACKUP COPY OF YOUR NAP BINARY BEFORE USING
   THIS PROGRAM. */

/* where to seek() in the stream to find the metaserver address */
#define OFFSET 0x005a79c /* nap v0.9 beta */
/* #define OFFSET 0x00596bc */ /* nap v0.8 beta */

int
main(int argc,char**argv)
{
	FILE *f;
	char meta[16];
	meta[15]=0;
	if(argc<2){
		puts("usage: patchnap <nap-binary> <meta-server>\n");
		exit(1);
	}
	f=fopen(argv[1],"r+");
	if (!f){
		perror(argv[1]);
		exit(1);
	}
	fseek(f,OFFSET,SEEK_SET);
	fread(meta,1,sizeof(meta)-1,f);
	printf("we've secretely replace your premium blend (%s) with folger's crytals (%s).\n", meta, argv[2]);
	fseek(f,OFFSET,SEEK_SET);
	fwrite(argv[2],1,strlen(argv[2])+1,f);
	fclose(f);
}
