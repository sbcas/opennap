/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* needed for the random number generation */
time_t Current_Time = 0;

static void
usage (void)
{
    fputs ("usage: mkpass [ -c INFO ] PASSWORD\n", stderr);
    exit (1);
}

int
main (int argc, char **argv)
{
    char *s, *pass = 0;
    int i;

    INIT ();
    while ((i = getopt (argc, argv, "c:vh")) != -1)
    {
	switch (i)
	{
	case 'c':
	    pass = optarg;
	    break;
	default:
	    usage ();
	}
    }

    if (!argv[optind])
	usage ();

    if (pass)
    {
	if (check_pass (pass, argv[optind]))
	    puts ("invalid password");
	else
	    puts ("OK");
    }
    else
    {
	init_random ();
	s = generate_pass (argv[optind]);
	puts (s);
	if (check_pass (s, argv[optind]))
	    puts ("error");
	FREE (s);
	CLEANUP ();
    }
    exit (0);
}
