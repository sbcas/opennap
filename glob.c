/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"

/* returns >0 if the pattern matches, 0 if the pattern does not match */
int
glob_match (const char *pattern, const char *s)
{
    const char *ptr;

    while (*pattern && *s)
    {
	if (*pattern == '*')
	{
	    while (*pattern == '*' || *pattern == '?')
		pattern++;
	    if (!*pattern)
	    {
		/* match to end of string */
		return 1;
	    }
	    /* recursively attempt to match the rest of the string, using the
	     * longest match first
	     */
	    ptr = s + strlen (s);
	    for (;;)
	    {
		while (ptr > s && *(ptr - 1) != *pattern)
		    ptr--;
		if (ptr == s)
		    return 0;	/* no match */
		if (glob_match (pattern+1, ptr))
		    return 1;
		ptr--;
	    }
	    /* not reached */
	}
	else if (*pattern == '?' || *pattern == *s)
	{
	    pattern++;
	    s++;
	}
	else
	    return 0;		/* no match */
    }
    return ((*pattern || *s) ? 0 : 1);
}
