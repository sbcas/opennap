/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#ifndef opennap_h
#define opennap_h

#include <stdarg.h>
#include <sys/types.h>
#include "hash.h"

#define MAGIC_USER 0xeaee402a
#define MAGIC_CHANNEL 0xa66544cb
#define MAGIC_HOTLIST 0xb0f8ad23
#define MAGIC_CONNECTION 0x3c4474a3

/* swap the bytes of a 16-bit integer */
#define BSWAP16(c) (((c & 0xff) << 4) | ((c >> 4) & 0xff))

typedef unsigned char uchar;

typedef struct _connection CONNECTION;
typedef struct _user USER;
typedef struct _channel CHANNEL;
typedef struct _hotlist HOTLIST;

struct _channel
{
#ifdef DEBUG
    unsigned long magic;
#endif
    char *name;
    char *topic;
    USER **users;
    int numusers;
    time_t created;
};

/* user flags */
#define FLAG_ADMIN	1
#define FLAG_MODERATOR	(1<<1)

struct _user
{
#ifdef DEBUG
    unsigned long magic;
#endif
    char *nick;
    char *clientinfo;
    unsigned short uploads;	/* no. of uploads in progress */
    unsigned short downloads;	/* no. of downloads in progress */
    unsigned short speed;	/* link speed */
    unsigned short shared;	/* # of shared files */
    unsigned long libsize;	/* approximate size of shared files in kB */
    unsigned long host;		/* ip of user in network byte order */
    int port;			/* data port client is listening on */
    int flags;
    time_t connected;		/* time at which the user connected */
    time_t muzzled;		/* time at which the user is allowed to post public msgs */

    CHANNEL **channels;		/* channels of which this user is a member */
    int numchannels;		/* number of channels */
    CONNECTION *con;		/* if locally connected */
    CONNECTION *serv;		/* the server behind which this user lies */
};

#define HAS_PRIVILEGE(x) (((x)->flags&(FLAG_ADMIN|FLAG_MODERATOR))!=0)

typedef enum
{
    CLASS_UNKNOWN,
    CLASS_USER,
    CLASS_SERVER
}
CLASS;

struct _connection
{
#ifdef DEBUG
    unsigned long magic;
#endif
    short id;			/* offset into the Client[] arrary for this
				   instance */
    short flags;		/* flags for the connection */
    int fd;			/* socket for this connection */
    unsigned long ip;
    char *host;			/* host from which this connection originates */
    CLASS class;		/* type of connection, server or client */
    USER *user;			/* pointer to the user associated with this
				   connection, if CLASS_USER */
    char *sendbuf;		/* queued data to send */
    int sendbuflen;		/* length of queued data */
    int sendbufmax;		/* memory allocated for queue */

    /* input buffer */
    char recvhdr[4];		/* packet header */
    char *recvdata;		/* packet body (data) */
    int recvbytes; /* bytes read, INCLUDING packet header */
    int recvdatamax; /* actual length of .recvdata buffer */

    /* server authentication */
    char *nonce;
    char *sendernonce;

    /* hotlist for user.  this is the list of users they wish to be
       notified about when they log in or out.  note that this is just a
       pointer to the _single_ global entry stored in the Hotlist hash table.
       the actual HOTLIST* pointer should only be freed when hotlist->numusers
       is zero.  */
    HOTLIST **hotlist;
    int hotlistsize;		/* number of hotlist entries */
};

/* hotlist entry */
struct _hotlist
{
#ifdef DEBUG
    unsigned long magic;
#endif
    char *nick;		/* user being monitored */
    CONNECTION **users;	/* list of local clients requesting notification */
    int numusers;	/* number of local clients requesting notification */
};

/* message types */
/* MSG_CLIENT_* are messages sent by the client to the server
   MSG_SERVER_* are messages sent by the server to the client

   note that in some cases CLIENT messages are sent to peer servers
   by the receiving server */

#define MSG_SERVER_ERROR		0
#define MSG_CLIENT_LOGIN		2
#define MSG_SERVER_EMAIL		3
#define MSG_CLIENT_LOGIN_REGISTER	6
#define MSG_CLIENT_REGISTER		7
#define MSG_SERVER_REGISTER_OK		8
#define MSG_SERVER_REGISTER_FAIL	9
#define MSG_SERVER_BAD_NICK		10
#define MSG_CLIENT_ADD_FILE		100
#define MSG_CLIENT_REMOVE_FILE		102
#define MSG_CLIENT_SEARCH		200
#define MSG_SERVER_SEARCH_RESULT	201
#define MSG_SERVER_SEARCH_END		202
#define MSG_CLIENT_DOWNLOAD		203
#define MSG_SERVER_FILE_READY		204
#define MSG_CLIENT_PRIVMSG		205
#define MSG_SERVER_SEND_ERROR		206
#define MSG_CLIENT_ADD_HOTLIST		207
#define MSG_CLIENT_ADD_HOTLIST_SEQ	208
#define MSG_SERVER_USER_SIGNON		209
#define MSG_SERVER_USER_SIGNOFF		210
#define MSG_CLIENT_BROWSE		211
#define MSG_SERVER_BROWSE_RESPONSE	212
#define MSG_SERVER_BROWSE_END		213
#define MSG_SERVER_STATS		214
#define MSG_CLIENT_RESUME_REQUEST	215
#define MSG_SERVER_RESUME_MATCH		216
#define MSG_SERVER_RESUME_MATCH_END	217
#define MSG_CLIENT_DOWNLOAD_START	218
#define MSG_CLIENT_DOWNLOAD_END		219
#define MSG_CLIENT_UPLOAD_START		220
#define MSG_CLIENT_UPLOAD_END		221
#define MSG_SERVER_HOTLIST_ACK		301
#define MSG_CLIENT_REMOVE_HOTLIST	303
#define MSG_CLIENT_JOIN			400
#define MSG_CLIENT_PART			401
#define MSG_CLIENT_PUBLIC		402
#define MSG_SERVER_PUBLIC		403
#define MSG_SERVER_NOSUCH		404
#define MSG_SERVER_JOIN_ACK		405
#define MSG_SERVER_JOIN			406
#define MSG_SERVER_PART			407
#define MSG_SERVER_CHANNEL_USER_LIST	408	/* list of users in a channel */
#define MSG_SERVER_CHANNEL_USER_LIST_END	409
#define MSG_SERVER_TOPIC		410	/* server and client */
#define MSG_CLIENT_DOWNLOAD_FIREWALL	500
#define MSG_SERVER_UPLOAD_FIREWALL	501
#define MSG_CLIENT_USERSPEED		600
#define MSG_SERVER_USER_SPEED		601
#define MSG_CLIENT_WHOIS		603	/* whois query */
#define MSG_SERVER_WHOIS_RESPONSE	604
#define MSG_CLIENT_SETUSERLEVEL		606
#define MSG_SERVER_UPLOAD_REQUEST	607
#define MSG_CLIENT_UPLOAD_OK		608
#define MSG_CLIENT_KILL			610
#define MSG_CLIENT_NUKE			611	/* not implemented */
#define MSG_CLIENT_LIST_CHANNELS	617
#define MSG_SERVER_CHANNEL_LIST_END	617
#define MSG_SERVER_CHANNEL_LIST		618
#define MSG_SERVER_MOTD			621
#define MSG_CLIENT_MUZZLE		622
#define MSG_CLIENT_UNMUZZLE		623
#define MSG_CLIENT_DATA_PORT_ERROR	626
#define MSG_SERVER_DATA_PORT_ERROR	626 /* same as client message */
#define MSG_CLIENT_WALLOP		627
#define MSG_CLIENT_ANNOUNCE		628
#define MSG_CLIENT_CHANGE_SPEED		700
#define MSG_CLIENT_CHANGE_DATA_PORT	703
#define MSG_CLIENT_PING			751
#define MSG_SERVER_PING			751
#define MSG_CLIENT_PONG			752
#define MSG_SERVER_PONG			752
#define MSG_SERVER_NAMES_LIST		825
#define MSG_SERVER_NAMES_LIST_END	830
#define MSG_CLIENT_NAMES_LIST		830

/* non-standard message unique to this server */
#define MSG_SERVER_ANNOUNCE		629	/* i assume its this? */
#define MSG_CLIENT_QUIT			10000	/* user has quit */
#define MSG_SERVER_LOGIN		10010	/* server login request */
#define MSG_SERVER_LOGIN_ACK		10011	/* server login response */
#define MSG_CLIENT_CONNECT		10012	/* user request for server
						   connect */
#define MSG_SERVER_USER_IP		10013	/* ip for user */

/* offsets into the row returned for library searches */
#define IDX_NICK	0
#define IDX_FILENAME	1
#define IDX_SIZE	2
#define IDX_MD5		3
#define IDX_BITRATE	4
#define IDX_FREQ	5
#define IDX_LENGTH	6
#define IDX_SPEED	7

extern char *Motd_Path;
extern char *Db_Host;
extern char *Db_User;
extern char *Db_Pass;
extern char *Db_Name;
extern char *Server_Name;
extern char *Server_Pass;
extern int Server_Port;

extern char Buf[1024];

extern HASH *Users;

extern CONNECTION **Clients;	/* locally connected clients */
extern int Num_Clients;

extern int Num_Files;		/* total number of available files */
extern int Num_Gigs;		/* total size of files available (in kB) */

extern CONNECTION **Servers;	/* peer servers */
extern int Num_Servers;

extern HASH *Channels;

extern HASH *Hotlist;

#define set_tag(b,n) set_val(b+2,n)
#define set_len set_val
void set_val (char *d, unsigned short val);

/* utility routines */
void add_client (CONNECTION *);
void add_server (CONNECTION *);
void *array_add (void *, int *, void *);
int array_remove (void *, int *, void *);
void close_db (void);
void config (const char *);
void expand_hex (char *, int);
void free_channel (CHANNEL *);
void free_hotlist (HOTLIST *);
void free_user (USER *);
void fudge_path (const char *, char *);
char *generate_nonce (void);
int init_db (void);
void log (const char *fmt, ...);
USER *new_user (void);
CHANNEL *new_channel (void);
HOTLIST *new_hotlist (void);
CONNECTION *new_connection (void);
void nosuchuser (CONNECTION *, char *);
void part_channel (CHANNEL *, USER *);
void pass_message (CONNECTION *, char *, size_t);
void pass_message_args (CONNECTION * con, unsigned long msgtype,
			const char *fmt, ...);
void permission_denied (CONNECTION *con);
int pop_user (CONNECTION * con, char **pkt, USER ** user);
void queue_data (CONNECTION *, char *, int);
size_t read_bytes (int, char *, size_t);
void remove_connection (CONNECTION *);
void remove_user (CONNECTION *);
void send_cmd (CONNECTION *, unsigned long msgtype, const char *fmt, ...);
int split_line (char **template, int templatecount, char *pkt);
void show_motd (CONNECTION * con);
void send_queued_data (CONNECTION *con);
void sql_error (const char *function, const char *query);
void synch_server (CONNECTION *);
int validate_user (USER *);
int validate_channel (CHANNEL *);
int validate_connection (CONNECTION *);
int validate_hotlist (HOTLIST *);

/* protocol handlers */
#define HANDLER(f) void f (CONNECTION *con, char *pkt)
HANDLER (add_file);
HANDLER (add_hotlist);
HANDLER (announce);
HANDLER (browse);
HANDLER (change_data_port);
HANDLER (change_speed);
HANDLER (client_quit);
HANDLER (data_port_error);
HANDLER (download);
HANDLER (download_end);
HANDLER (download_start);
HANDLER (join);
HANDLER (kill_user);
HANDLER (level);
HANDLER (list_channels);
HANDLER (list_users);
HANDLER (login);
HANDLER (muzzle);
HANDLER (nuke_user);
HANDLER (privmsg);
HANDLER (part);
HANDLER (ping);
HANDLER (pong);
HANDLER (public);
HANDLER (remove_file);
HANDLER (remove_hotlist);
HANDLER (resume);
HANDLER (search);
HANDLER (server_connect);
HANDLER (server_login);
HANDLER (server_login_ack);
HANDLER (server_stats);
HANDLER (unmuzzle);
HANDLER (upload_ok);
HANDLER (upload_start);
HANDLER (upload_end);
HANDLER (topic);
HANDLER (user_ip);
HANDLER (user_speed);
HANDLER (whois);

#define CHECK_USER_CLASS(f) if (con->class != CLASS_USER) { log ("%s: not USER class", f); return; }
#define CHECK_SERVER_CLASS(f) if(con->class != CLASS_SERVER) { log ("%s: not SERVER class", f); return; }

#endif /* opennap_h */
