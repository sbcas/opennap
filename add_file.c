/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

/* allowed bitrates for MPEG V1/V2 Layer III */
const int BitRate[18] =
    { 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 192, 224,
	256, 320 };

/* allowed sample rates for MPEG V2/3 */
const int SampleRate[6] = { 16000, 24000, 22050, 32000, 44100, 48000 };

static void
fdb_add (HASH * table, char *key, DATUM * d)
{
    FLIST *files;
    LIST *list;

    ASSERT (table != 0);
    ASSERT (key != 0);
    ASSERT (d != 0);
    files = hash_lookup (table, key);
    /* if there is no entry for this particular word, create one now */
    if (!files)
    {
	files = CALLOC (1, sizeof (FLIST));
	if (!files)
	{
	    OUTOFMEMORY ("fdb_add");
	    return;
	}
	files->key = STRDUP (key);
	if (!files->key)
	{
	    OUTOFMEMORY ("fdb_add");
	    FREE (files);
	    return;
	}
	if (hash_add (table, files->key, files))
	{
	    FREE (files->key);
	    FREE (files);
	    return;
	}
    }
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("list");
	if (!files->list)
	    hash_remove (table, files->key);
	return;
    }
    list->data = d;
    files->list = list_append (files->list, list);
    files->count++;
    d->refcount++;
}

/* common code for inserting a file into the various hash tables */
static void
insert_datum (DATUM * info, char *av)
{
    LIST *tokens, *ptr;
    int fsize;

    ASSERT (info != 0);
    ASSERT (av != 0);

    if (!info->user->con->uopt->files)
    {
	/* create the hash table */
	info->user->con->uopt->files =
	    hash_init (257, (hash_destroy) free_datum);
	if (!info->user->con->uopt->files)
	{
	    OUTOFMEMORY ("insert_datum");
	    return;
	}
    }

    hash_add (info->user->con->uopt->files, info->filename, info);
    info->refcount++;

    /* split the filename into words */
    tokens = tokenize (av);

    /* the filename may not consist of any searchable words, in which
     * case its not entered into the index.  this file will only be seen
     * when browsing the user possessing it
     */
    if(tokens)
    {
	/* add this entry to the global file list.  the data entry currently
	   can't be referenced more than 32 times so if there are excess tokens,
	   discard the first several so that the refcount is not overflowed */
	fsize = list_count (tokens);
	ptr = tokens;
	while (fsize > 30)
	{
	    ptr = ptr->next;
	    fsize--;
	}
	for (; ptr; ptr = ptr->next)
	    fdb_add (File_Table, ptr->data, info);

	list_free (tokens, 0);
    }

#if RESUME
    /* index by md5 hash */
    fdb_add (MD5, info->hash, info);
#endif

    fsize = info->size / 1024;
    info->user->shared++;
    info->user->libsize += fsize;
    Num_Gigs += fsize;		/* this is actually kB, not gB */
    Num_Files++;
    Local_Files++;
    info->user->sharing = 1;	/* note that we began sharing */
}

static DATUM *
new_datum (char *filename, char *hash)
{
    DATUM *info = CALLOC (1, sizeof (DATUM));

    (void) hash;
    if (!info)
    {
	OUTOFMEMORY ("new_datum");
	return 0;
    }
    info->filename = STRDUP (filename);
    if (!info->filename)
    {
	OUTOFMEMORY ("new_datum");
	FREE (info);
	return 0;
    }
#if RESUME
    info->hash = STRDUP (hash);
    if (!info->hash)
    {
	OUTOFMEMORY ("new_datum");
	FREE (info->filename);
	FREE (info);
	return 0;
    }
#endif
    return info;
}

static int
bitrateToMask (int bitrate, USER * user)
{
    unsigned int i;

    for (i = 0; i < sizeof (BitRate) / sizeof (int); i++)

    {
	if (bitrate <= BitRate[i])
	    return i;
    }
    log ("bitrateToMask(): invalid bit rate %d (%s, \"%s\")", bitrate,
	 user->nick, user->clientinfo);
    return 0;			/* invalid bitrate */
}

static int
freqToMask (int freq, USER * user)
{
    unsigned int i;
    for (i = 0; i < sizeof (SampleRate) / sizeof (int); i++)

    {
	if (freq <= SampleRate[i])
	    return i;
    }
    log ("freqToMask(): invalid sample rate %d (%s, \"%s\")", freq,
	 user->nick, user->clientinfo);
    return 0;
}

/* 100 "<filename>" <md5sum> <size> <bitrate> <frequency> <time>
   client adding file to the shared database */
HANDLER (add_file)
{
    char *av[6];
    DATUM *info;
    int fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("add_file");

    ASSERT (validate_user (con->user));

    if (Max_Shared && con->user->shared > Max_Shared)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "You may only share %d files", Max_Shared);
	return;
    }

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 6)
    {
	unparsable(con);
	return;
    }

    if (av[1] - av[0] > _POSIX_PATH_MAX + 2)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "filename too long");
	return;
    }

    /* ensure we have a valid byte count */
    fsize = atoi (av[2]);
    if (fsize < 1)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid file size");
	return;
    }

    /* make sure this isn't a duplicate - only compare the basename, not
     * including the directory component
     */
    if (con->uopt->files && hash_lookup (con->uopt->files, av[0]))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "duplicate file");
	return;
    }

    /* create the db record for this file */
    if (!(info = new_datum (av[0], av[1])))
	return;
    info->user = con->user;
    info->size = fsize;
    info->bitrate = bitrateToMask (atoi (av[3]), con->user);
    info->frequency = freqToMask (atoi (av[4]), con->user);
    info->duration = atoi (av[5]);
    info->type = CT_MP3;

    insert_datum (info, av[0]);
}

char *Content_Types[] = {
    "mp3",			/* not a real type, but what we use for audio/mp3 */
    "audio",
    "video",
    "application",
    "image",
    "text"
};

/* 10300 "<filename>" <size> <hash> <content-type> */
HANDLER (share_file)
{
    char *av[4];
    DATUM *info;
    int i, type;

    (void) len;
    (void) tag;

    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("share_file");

    if (Max_Shared && con->user->shared > Max_Shared)
    {
	log ("add_file(): %s is already sharing %d files", con->user->nick,
	     con->user->shared);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "You may only share %d files", Max_Shared);
	return;
    }

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 4)
    {
	unparsable (con);
	return;
    }

    /* make sure the content-type looks correct */
    type = -1;
    for (i = CT_AUDIO; i < CT_UNKNOWN; i++)
    {
	if (!strcasecmp (Content_Types[i], av[3]))
	{
	    type = i;
	    break;
	}
    }
    if (type == -1)
    {
	log ("share_file(): not a valid type: %s", av[3]);
	if (ISUSER (con) == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not a valid type",
		      av[3]);
	return;
    }

    if (av[1] - av[0] > _POSIX_PATH_MAX + 2)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "filename too long");
	return;
    }

    if (con->uopt->files && hash_lookup (con->uopt->files, av[0]))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "duplicate file");
	return;
    }

    if (!(info = new_datum (av[0], av[2])))
	return;
    info->user = con->user;
    info->size = atoi (av[1]);
    info->type = type;

    insert_datum (info, av[0]);
}

/* 10012 <nick> <shared> <size>
   remote server is notifying us that one of its users is sharing files */
HANDLER (user_sharing)
{
    char *av[3];
    USER *user;
    int deltanum, deltasize;

    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("user_sharing");
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 3)
    {
	log ("user_sharing(): wrong number of arguments");
	return;
    }
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	log ("user_sharing(): no such user %s (from %s)", av[0], con->host);
	return;
    }
    deltanum = atoi (av[1]) - user->shared;
    Num_Files += deltanum;
    user->shared += deltanum;
    deltasize = atoi (av[2]) - user->libsize;
    Num_Gigs += deltasize;
    user->libsize += deltasize;
    pass_message_args (con, tag, "%s %d %d", user->nick, user->shared,
		       user->libsize);
}

/* 870 "<directory>" "<basename>" <md5> <size> <bitrate> <freq> <duration> [ ... ]
   client command to add multiple files in the same directory */
HANDLER (add_directory)
{
    char *dir, *basename, *md5, *size, *bitrate, *freq, *duration;
    char path[_POSIX_PATH_MAX], dirbuf[_POSIX_PATH_MAX];
    int pathlen;
    DATUM *info;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("add_directory");
    dir = next_arg (&pkt);	/* directory */
    if (!dir)
    {
	log ("add_directory(): missing directory component");
	return;
    }
    pathlen = strlen (dir);
    if ((size_t) pathlen >= sizeof (dirbuf) - 1)
    {
	log ("add_directory(): directory component is too long, ignoring");
	return;
    }
    ASSERT(pathlen<sizeof(dirbuf)-1);
    dirbuf[sizeof (dirbuf) - 1] = 0;	/* ensure nul termination */
    strncpy (dirbuf, dir, sizeof (dirbuf) - 1);

    if (pathlen > 0 && dirbuf[pathlen - 1] != '\\')
    {
	dirbuf[pathlen++]='\\';
	dirbuf[pathlen]=0;
	if ((size_t) pathlen >= sizeof (dirbuf) - 1)
	{
	    ASSERT ((size_t) pathlen < sizeof (dirbuf));
	    log
		("add_directory(): directory component is too long, ignoring");
	    return;
	}
    }

    /* if the client passes a dir + file that is longer than 255 chars,
     * strncpy() won't write a \0 at the end of the string, so ensure that
     * this always happens
     */
    path[sizeof(path)-1]=0;

    while (pkt)
    {
	if (Max_Shared && con->user->shared > Max_Shared)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "You may only share %d files", Max_Shared);
	    return;
	}
	basename = next_arg (&pkt);
	md5 = next_arg (&pkt);
	size = next_arg (&pkt);
	bitrate = next_arg (&pkt);
	freq = next_arg (&pkt);
	duration = next_arg (&pkt);
	if (!basename || !md5 || !size || !bitrate || !freq || !duration)
	{
	    unparsable (con);
	    return;
	}

	strncpy(path,dirbuf,sizeof(path)-1);
	strncpy(path+pathlen,basename,sizeof(path)-1-pathlen);

	ASSERT(path[sizeof(path)-1]==0);

	/* TODO: still seeing crashes here, we must be overwriting the
	 * stack on occasion.  quit now if we detect this condition
	 */
	if(path[sizeof(path)-1] != 0)
	{
	    log("add_directory(): ERROR! buffer overflow detected");
	    return;
	}


	if (con->uopt->files && hash_lookup (con->uopt->files, path))
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "Duplicate file");
	    continue;		/* get next file */
	}

	/* create the db record for this file */
	if (!(info = new_datum (path, md5)))
	    return;
	info->user = con->user;
	info->size = atoi (size);
	info->bitrate = bitrateToMask (atoi (bitrate), con->user);
	info->frequency = freqToMask (atoi (freq), con->user);
	info->duration = atoi (duration);
	info->type = CT_MP3;

	insert_datum (info, path);
    }
}
