/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
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
    {MSG_CLIENT_REGISTER, register_nick}, /* 7 */
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
    {MSG_CLIENT_CHANGE_DATA_PORT, change_data_port}, /* 703 */
    {MSG_CLIENT_PING, ping},	/* 751 */
    {MSG_CLIENT_PONG, ping},	/* 752 */
    {MSG_CLIENT_SERVER_RECONFIG, server_reconfig},	/* 800 */
    {MSG_CLIENT_SERVER_VERSION, server_version},	/* 801 */
    {MSG_CLIENT_SERVER_CONFIG, server_config},	/* 810 */
    {MSG_CLIENT_EMOTE, emote},	/* 824 */
    {MSG_CLIENT_NAMES_LIST, list_users},	/* 830 */

    /* non-standard messages */
    {MSG_CLIENT_QUIT, client_quit},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_SERVER_LOGIN_ACK, server_login_ack},
    {MSG_SERVER_USER_IP, user_ip},		/* 10013 */
    {MSG_SERVER_REGINFO, reginfo },		/* 10014 */
    {MSG_CLIENT_CONNECT, server_connect},	/* 10100 */
    {MSG_CLIENT_DISCONNECT, server_disconnect},	/* 10101 */
    {MSG_CLIENT_KILL_SERVER, kill_server},	/* 10110 */
    {MSG_CLIENT_REMOVE_SERVER, remove_server},	/* 10111 */
    {MSG_CLIENT_LINKS, server_links },		/* 10112 */
    {MSG_CLIENT_USAGE_STATS, server_usage },	/* 10115 */
#if 0
    {MSG_SERVER_COMPRESSED_DATA, compressed_data},	/* 10200 */
#endif
    {MSG_CLIENT_SHARE_FILE, share_file},
    {MSG_SERVER_REMOTE_ERROR, priv_errmsg},	/* 10404 */
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
       handlers.  the buffer_read() function should always allocate 1 byte
       more than necessary for this purpose */
    ASSERT (VALID_LEN (con->recvbuf->data, con->recvbuf->consumed + 4 + len + 1));
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
    unsigned short len, tag;

    ASSERT (validate_connection (con));

#if HAVE_LIBZ
    /* decompress server input stream */
    if (ISSERVER (con))
    {
	BUFFER *b;

	if (con->sopt->inbuf
	    && (b = buffer_uncompress (con->sopt->zin, &con->sopt->inbuf)))
	    con->recvbuf = buffer_append (con->recvbuf, b);
    }
#endif /* HAVE_LIBZ */

    /* check if there is enough data in the buffer to read the packet header */
    if (buffer_size (con->recvbuf) < 4)
    {
	/* we set this flag here to avoid busy waiting in the main select()
	   loop.  we can't process any more input until we get some more
	   data */
	con->incomplete = 1;
	return;
    }
    /* make sure all 4 bytes of the header are in the first block */
    if (buffer_group (con->recvbuf, 4) == -1)
    {
	/* probably a memory allocation error, close this connection since
	   we can't handle it */
	log ("handle_connection(): could not read packet header from buffer");
	con->destroy = 1;
	return;
    }
    memcpy (&len, con->recvbuf->data + con->recvbuf->consumed, 2);
    memcpy (&tag, con->recvbuf->data + con->recvbuf->consumed + 2, 2);

    /* need to convert to little endian */
    len = BSWAP16 (len);
    tag = BSWAP16 (tag);

    /* see if all of the packet body is present */
    if (buffer_size (con->recvbuf) < 4 + len)
    {
	/* nope, wait until more data arrives */
#if 0
	log ("handle_connection(): waiting for %d bytes from client (tag=%d)",
		len, tag);
#endif
	con->incomplete = 1;
	return;
    }

    con->incomplete = 0;	/* found all the data we wanted */

    /* the packet may be fragmented so make sure all of the bytes for this
       packet end up in the first buffer so its easy to handle */
    if (buffer_group (con->recvbuf, 4 + len) == -1)
    {
	/* probably a memory allocation error, close this connection since
	   we can't handle it */
	log ("handle_connection(): could not read packet body from buffer");
	con->destroy = 1;
	return;
    }

#ifndef HAVE_DEV_RANDOM
    add_random_bytes (con->recvbuf->data + con->recvbuf->consumed, 4 + len);
#endif /* !HAVE_DEV_RANDOM */

    /* require that the client register before doing anything else */
    if (con->class == CLASS_UNKNOWN &&
	(tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
	 tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
	 tag != MSG_SERVER_LOGIN_ACK && tag != MSG_SERVER_ERROR &&
	 tag != 4)) /* unknown: v2.0 beta 5a sends this? */
    {
	log ("handle_connection(): %s is not registered, closing connection",
	     con->host);
	log ("handle_connection(): tag=%hu, len=%hu, data=%s",
		tag, len, con->recvbuf->data + con->recvbuf->consumed + 4);
	con->destroy = 1;
	return;
    }

    /* if we received this message from a peer server, pass it
       along to the other servers behind us.  the ONLY messages we don't
       propogate are an ACK from a peer server that we've requested a link
       with, and an error message from a peer server */
    if (con->class == CLASS_SERVER && tag != MSG_SERVER_LOGIN_ACK &&
	tag != MSG_SERVER_ERROR && tag != MSG_SERVER_NOSUCH && Num_Servers)
	pass_message (con, con->recvbuf->data + con->recvbuf->consumed,
		      4 + len);

    dispatch_command (con, tag, len,
		      con->recvbuf->data + con->recvbuf->consumed + 4);

    /* mark that we read this data and it is ok to free it */
    con->recvbuf = buffer_consume (con->recvbuf, len + 4);
}
