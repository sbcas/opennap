/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <errno.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

HANDLER (server_stats)
{
    (void) pkt;
    (void) tag;
    (void) len;
    send_cmd (con, MSG_SERVER_STATS, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs / (1024 * 1024));
}

/* 10018 :<server> <target> <packet>
   allows a server to send an arbitrary message to a remote user */
HANDLER (encapsulated)
{
    char *nick, ch, *ptr;
    USER *user;

    (void) tag;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("encapsulated");
    if (*pkt != ':')
    {
	log
	    ("encapsulated(): server message does not begin with a colon (:)");
	return;
    }
    nick = strchr (pkt + 1, ' ');
    nick++;
    ptr = strchr (nick, ' ');
    ch = *ptr;
    *ptr = 0;
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log ("encapsulated(): no such user %s", nick);
	return;
    }
    if (user->local)
    {
	ptr++;
	queue_data (user->con, ptr, len - (ptr - pkt));
    }
    else if (Num_Servers > 1)
    {
	*ptr = ch;
	pass_message (con, pkt, len);
    }
}

typedef struct
{
    unsigned int message;
      HANDLER ((*handler));
}
HANDLER;

/* this is the table of valid commands we accept from both users and servers */
static HANDLER Protocol[] = {
    {MSG_CLIENT_LOGIN, login},	/* 2 */
    {MSG_CLIENT_LOGIN_REGISTER, login},	/* 6 */
    {MSG_CLIENT_REGISTER, register_nick},	/* 7 */
    {MSG_CLIENT_ADD_FILE, add_file},	/* 100 */
    {MSG_CLIENT_REMOVE_FILE, remove_file},	/* 102 */
    {MSG_CLIENT_SEARCH, search},	/* 200 */
    {MSG_CLIENT_PRIVMSG, privmsg},	/* 205 */
    {MSG_CLIENT_ADD_HOTLIST, add_hotlist},	/* 207 */
    {MSG_CLIENT_ADD_HOTLIST_SEQ, add_hotlist},	/* 208 */
    {MSG_CLIENT_BROWSE, browse},	/* 211 */
    {MSG_SERVER_STATS, server_stats},	/* 214 */
    {MSG_CLIENT_RESUME_REQUEST, resume},	/* 215 */
    {MSG_CLIENT_DOWNLOAD_START, download_start},	/* 218 */
    {MSG_CLIENT_DOWNLOAD_END, download_end},	/* 219 */
    {MSG_CLIENT_UPLOAD_START, upload_start},	/* 220 */
    {MSG_CLIENT_UPLOAD_END, upload_end},	/* 221 */
    {MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist},	/* 303 */
    {MSG_SERVER_NOSUCH, server_error},	/* 404 */
    {MSG_CLIENT_DOWNLOAD_FIREWALL, download},	/* 500 */
    {MSG_CLIENT_WHOIS, whois},
    {MSG_CLIENT_JOIN, join},
    {MSG_CLIENT_PART, part},
    {MSG_CLIENT_PUBLIC, public},
    {MSG_SERVER_PUBLIC, public},
    {MSG_CLIENT_USERSPEED, user_speed},	/* 600 */
    {MSG_CLIENT_KILL, kill_user},
    {MSG_CLIENT_DOWNLOAD, download},
    {MSG_CLIENT_UPLOAD_OK, upload_ok},
    {MSG_SERVER_UPLOAD_REQUEST, upload_request},	/* 607 */
    {MSG_SERVER_TOPIC, topic},
    {MSG_CLIENT_MUZZLE, muzzle},
    {MSG_CLIENT_UNMUZZLE, unmuzzle},
    {MSG_CLIENT_BAN, ban},	/* 612 */
    {MSG_CLIENT_ALTER_PORT, alter_port},	/* 613 */
    {MSG_CLIENT_UNBAN, unban},	/* 614 */
    {MSG_CLIENT_BANLIST, banlist},	/* 615 */
    {MSG_CLIENT_LIST_CHANNELS, list_channels},	/* 618 */
    {MSG_CLIENT_LIMIT, queue_limit},	/* 619 */
    {MSG_CLIENT_MOTD, show_motd},	/* 621 */
    {MSG_CLIENT_DATA_PORT_ERROR, data_port_error},	/* 626 */
    {MSG_CLIENT_WALLOP, wallop},	/* 627 */
    {MSG_CLIENT_ANNOUNCE, announce},	/* 628 */
    {MSG_CLIENT_SETUSERLEVEL, level},
    {MSG_CLIENT_CHANGE_SPEED, change_speed},	/* 700 */
    {MSG_CLIENT_CHANGE_PASS, change_pass},	/* 701 */
    {MSG_CLIENT_CHANGE_EMAIL, change_email},	/* 702 */
    {MSG_CLIENT_CHANGE_DATA_PORT, change_data_port},	/* 703 */
    {MSG_CLIENT_PING, ping},	/* 751 */
    {MSG_CLIENT_PONG, ping},	/* 752 */
    {MSG_CLIENT_SERVER_RECONFIG, server_reconfig},	/* 800 */
    {MSG_CLIENT_SERVER_VERSION, server_version},	/* 801 */
    {MSG_CLIENT_SERVER_CONFIG, server_config},	/* 810 */
    {MSG_CLIENT_EMOTE, emote},	/* 824 */
    {MSG_CLIENT_NAMES_LIST, list_users},	/* 830 */

    /* non-standard messages */
    {MSG_CLIENT_QUIT, client_quit},
    {MSG_SERVER_LOGIN, server_login},	/* 10010 */
    {MSG_SERVER_LOGIN_ACK, server_login_ack},	/* 10011 */
    {MSG_SERVER_USER_SHARING, user_sharing},	/* 10012 */
    {MSG_SERVER_USER_IP, user_ip},	/* 10013 */
    {MSG_SERVER_REGINFO, reginfo},	/* 10014 */
    {MSG_SERVER_REMOTE_SEARCH, remote_search},	/* 10015 */
    {MSG_SERVER_REMOTE_SEARCH_RESULT, remote_search_result},	/* 10016 */
    {MSG_SERVER_REMOTE_SEARCH_END, remote_search_end},	/* 10017 */
    {MSG_SERVER_ENCAPSULATED, encapsulated},	/* 10018 */
    {MSG_CLIENT_CONNECT, server_connect},	/* 10100 */
    {MSG_CLIENT_DISCONNECT, server_disconnect},	/* 10101 */
    {MSG_CLIENT_KILL_SERVER, kill_server},	/* 10110 */
    {MSG_CLIENT_REMOVE_SERVER, remove_server},	/* 10111 */
    {MSG_CLIENT_LINKS, server_links},	/* 10112 */
    {MSG_CLIENT_USAGE_STATS, server_usage},	/* 10115 */
    {MSG_CLIENT_SHARE_FILE, share_file},
};
static int Protocol_Size = sizeof (Protocol) / sizeof (HANDLER);

/* this is not a real handler, but takes the same arguments as one */
HANDLER (dispatch_command)
{
    int l;
    unsigned char byte;

    ASSERT (validate_connection (con));

    /* HACK ALERT
       the handler routines all assume that the `pkt' argument is nul (\0)
       terminated, so we have to replace the byte after the last byte in
       this packet with a \0 to make sure we dont read overflow in the
       handlers.  the handle_connection() function should always allocate 1
       byte more than necessary for this purpose */
    ASSERT (VALID_LEN
	    (con->recvbuf->data, con->recvbuf->consumed + 4 + len + 1));
    byte = *(pkt + len);
    *(pkt + len) = 0;

    for (l = 0; l < Protocol_Size; l++)
    {
	if (Protocol[l].message == tag)
	{
	    ASSERT (Protocol[l].handler != 0);
	    /* note that we pass only the data part of the packet */
	    Protocol[l].handler (con, tag, len, pkt);
	    break;
	}
    }

    if (l == Protocol_Size)
    {
	log
	    ("dispatch_command(): unknown message: tag=%hu, length=%hu, data=%s",
	     tag, len,
	     len ? (char *) con->recvbuf->data +
	     con->recvbuf->consumed + 4 : "(empty)");

	send_cmd (con, MSG_SERVER_NOSUCH, "unknown command code %hu", tag);
    }

    /* restore the byte we overwrite at the beginning of this function */
    *(pkt + len) = byte;
}

void
handle_connection (CONNECTION * con)
{
    int n;
    unsigned short tag, len;

    ASSERT (validate_connection (con));

    if (ISSERVER (con))
    {
	/* server data is compressed.  read as much as we can and pass it
	   to the decompressor */
	n = read (con->fd, Buf, sizeof (Buf));
	if (n <= 0)
	{
	    if (n == -1)
	    {
		log ("handle_connection(): read: %s (errno %d)",
			strerror (errno), errno);
	    }
	    else
		log ("handle_connection(): EOF from %s", con->host);
	    con->destroy = 1;
	    return;
	}
	if (buffer_decompress (con->recvbuf, con->sopt->zin, Buf, n))
	{
	    con->destroy = 1;
	    return;
	}
    }
    else
    {
	/* create the input buffer if it doesn't yet exist */
	if (!con->recvbuf)
	{
	    con->recvbuf = CALLOC (1, sizeof (BUFFER));
	    if (!con->recvbuf)
	    {
		OUTOFMEMORY ("handle_connection");
		con->destroy = 1;
		return;
	    }
#if DEBUG
	    con->recvbuf->magic = MAGIC_BUFFER;
#endif
	    con->recvbuf->data = MALLOC (5);
	    if (!con->recvbuf->data)
	    {
		OUTOFMEMORY ("handle_connection");
		con->destroy = 1;
		return;
	    }
	    con->recvbuf->datamax = 4;
	}
	/* read the packet header if we haven't seen it already */
	if (con->recvbuf->datasize < 4)
	{
	    n = read (con->fd, con->recvbuf->data, 4);
	    if (n <= 0)
	    {
		if (n == -1)
		    log ("handle_connection(): read: %s (errno %d)",
			 strerror (errno), errno);
		else
		    log ("handle_connection(): EOF from %s", con->host);
		con->destroy = 1;
		return;
	    }
	    con->recvbuf->datasize = n;
	}
	/* read the packet body */
	memcpy (&len, con->recvbuf->data, 2);
	len = BSWAP16 (len);
	if (len > 0)
	{
	    /* if there isn't enough space to read the entire body, resize the
	       input buffer */
	    if (con->recvbuf->datamax < 4 + len)
	    {
		/* allocate 1 extra byte for the \0 that dispatch_command()
		   requires */
		if (safe_realloc ((void **) &con->recvbuf->data, 4 + len + 1))
		{
		    OUTOFMEMORY ("handle_connection");
		    con->destroy = 1;
		    return;
		}
		con->recvbuf->datamax = 4 + len;
	    }
	    n = read (con->fd, con->recvbuf->data + con->recvbuf->datasize,
		    len + 4 - con->recvbuf->datasize);
	    if (n == -1)
	    {
		/* since the header and body could arrive in separate packets,
		   we have to check for this here so we don't close the
		   connection on this nonfatal error.  we just wait for the
		   next packet to arrive */
		if (errno != EWOULDBLOCK)
		{
		    log ("handle_connection(): read: %s (errno %d)",
			    strerror (errno), errno);
		    con->destroy = 1;
		}
		return;
	    }
	    else if (n == 0)
	    {
		log ("handle_connection(): EOF from %s", con->host);
		con->destroy = 1;
		return;
	    }
	    con->recvbuf->datasize += n;
	}
    }
    /* process as many complete commands as possible.  for a client this
       will be exactly one, but a server link may have sent multiple commands
       in one compressed packet */
    while (con->recvbuf->consumed < con->recvbuf->datasize)
    {
	/* if we don't have the complete packet header, wait until we
	   read more data */
	if (con->recvbuf->datasize - con->recvbuf->consumed < 4)
	    break;
	/* read the packet header */
	memcpy (&len, con->recvbuf->data + con->recvbuf->consumed, 2);
	memcpy (&tag, con->recvbuf->data + con->recvbuf->consumed + 2, 2);
	len = BSWAP16 (len);
	tag = BSWAP16 (tag);
	/* check if the entire packet body has arrived */
	if (con->recvbuf->consumed + 4 + len > con->recvbuf->datasize)
	    break;
	/* add this data to the random pool */
	add_random_bytes (con->recvbuf->data + con->recvbuf->consumed,
		4 + len);
	/* require that the client register before doing anything else */
	if (con->class == CLASS_UNKNOWN &&
		(tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
		 tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
		 tag != MSG_SERVER_LOGIN_ACK && tag != MSG_SERVER_ERROR &&
		 tag != 4))	/* unknown: v2.0 beta 5a sends this? */
	{
	    log
		("handle_connection(): %s is not registered, closing connection",
		 con->host);
	    log ("handle_connection(): tag=%hu, len=%hu, data=%s", tag, len,
		    con->recvbuf->data + con->recvbuf->consumed + 4);
	    con->destroy = 1;
	    return;
	}
	/* call the protocol handler */
	dispatch_command (con, tag, len,
		con->recvbuf->data + con->recvbuf->consumed + 4);
	/* mark data as processed */
	con->recvbuf->consumed += 4 + len;
    }
    if (con->recvbuf->consumed)
    {
	n = con->recvbuf->datasize - con->recvbuf->consumed;
	if (n > 0)
	{
	    /* shift down unprocessed data */
	    memmove (con->recvbuf->data,
		    con->recvbuf->data + con->recvbuf->consumed, n);
	    log ("get_input(): %d unprocessed bytes left in buffer", n);
	}
	con->recvbuf->datasize = n;
	con->recvbuf->consumed = 0;	/* reset */
    }
}
