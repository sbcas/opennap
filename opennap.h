/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef opennap_h
#define opennap_h

#ifdef WIN32
#include <windows.h>
#endif
#include <stdarg.h>
#include <sys/types.h>
#if HAVE_LIBZ
#include <zlib.h>
#endif /* HAVE LIBZ */
#include "hash.h"

#define MAGIC_USER 0xeaee402a
#define MAGIC_CHANNEL 0xa66544cb
#define MAGIC_HOTLIST 0xb0f8ad23
#define MAGIC_CONNECTION 0x3c4474a3
#define MAGIC_BUFFER 0xe5a7a3be

/* convert the bytes of a 16-bit integer to little endian */
#if WORDS_BIGENDIAN
#define BSWAP16(c) (((c & 0xff) << 8) | ((c >> 8) & 0xff))
#define BSWAP32(c) (((c >> 24) & 0xff) | ((c & 0xff0000) >> 8) | ((c & 0xff00) << 8) | (c << 24))
#else
#define BSWAP16(c) c
#define BSWAP32(c) c
#endif

#define ISSPACE(c) isspace((unsigned char)c)

typedef unsigned char uchar;

typedef struct _buffer BUFFER;

/* to avoid copying a lot of data around with memmove() we use the following
   structure for output buffers */
struct _buffer
{
#if DEBUG
    unsigned int magic;
#endif
    char *data;		/* allocated data */
    int datasize;	/* total bytes used in `data' */
    int datamax;	/* size of allocated memory block */
    int consumed;	/* how many bytes of data consumed from this buffer */
    BUFFER *next;
};

/* this is not used when compiling without compression, but it makes the
   main event loop simpiler to code if we still define this here */
typedef struct {
#if HAVE_LIBZ
    z_streamp zin;	/* input stream decompressor */
    z_streamp zout;	/* output stream compressor */
#endif
    BUFFER *outbuf;	/* compressed output buffer */
    BUFFER *inbuf;	/* uncompressed input buffer */
} ZIP;

typedef struct _connection CONNECTION;
typedef struct _user USER;
typedef struct _channel CHANNEL;
typedef struct _hotlist HOTLIST;

struct _channel
{
#ifdef DEBUG
    unsigned int magic;
#endif
    char *name;
    char *topic;
    USER **users;
    int numusers;
    time_t created;
};

/* user level */
typedef enum {
    LEVEL_LEECH,
    LEVEL_USER,
    LEVEL_MODERATOR,
    LEVEL_ADMIN,
    LEVEL_ELITE
} LEVEL;

struct _user
{
#ifdef DEBUG
    unsigned int magic;
#endif
    char *nick;
    char *pass;			/* password for this user */
    char *clientinfo;
    char *email;		/* user's email address */
    char *server;		/* which server the user is connected to */
    unsigned short uploads;	/* no. of uploads in progress */
    unsigned short downloads;	/* no. of downloads in progress */
    unsigned short speed;	/* link speed */
    unsigned short shared;	/* # of shared files */
    unsigned short totalup;	/* total number of uploads */
    unsigned short totaldown;	/* total number of downloads */
    unsigned int libsize;	/* approximate size of shared files in kB */
    unsigned int host;		/* ip of user in network byte order */
    unsigned short port;	/* data port client is listening on */
    unsigned short conport;	/* remote port for connection to server */
    LEVEL level;		/* user level */
    time_t connected;		/* time at which the user connected */
    int muzzled;		/* non-zero if this user is muzzled */

    HASH *files;		/* db entries for this user's shared files */

    CHANNEL **channels;		/* channels of which this user is a member */
    int numchannels;		/* number of channels */
    CONNECTION *con;		/* if locally connected */
    CONNECTION *serv;		/* the server behind which this user lies */
};

typedef enum
{
    CLASS_UNKNOWN,
    CLASS_USER,
    CLASS_SERVER
}
CLASS;

/* this flag is set when we are in the process of connect()ing to another
   server, so that we know to select() the socket to complete the
   link */
#define FLAG_CONNECTING	1

struct _connection
{
#ifdef DEBUG
    unsigned int magic;
#endif
    short id;			/* offset into the Client[] arrary for this
				   instance */
    unsigned short flags;	/* flags for the connection */
    int fd;			/* socket for this connection */
    unsigned int ip;
    unsigned int port;		/* remote port */
    char *host;			/* host from which this connection originates */
    CLASS class;		/* type of connection, server or client */
    USER *user;			/* pointer to the user associated with this
				   connection, if CLASS_USER */

    BUFFER *sendbuf;		/* output buffer */

    /* the next three fields make up 4 bytes and should be grouped together
       to keep memory alignment correct */

    short compress;		/* compression level for this connection */
    char destroy;		/* connection should be destoyed in
				   handle_connection().  because h_c() caches
				   a copy of the CONNECTION pointer, we can't
				   remove it from inside a handler, so we mark
				   it here and have it removed at a later time 
				   when it is safe */
    char incomplete;		/* not enough data present to form a complete
				   packet */

    ZIP *zip;			/* compression stream state */

    BUFFER *recvbuf;		/* input buffer */

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
    unsigned int magic;
#endif
    char *nick;		/* user being monitored */
    CONNECTION **users;	/* list of local clients requesting notification */
    int numusers;	/* number of local clients requesting notification */
};

typedef struct list LIST;
struct list
{
    void *data;
    struct list *next;
};

/* list of DATUM entries, used in the global file list */
typedef struct {
    char *key;	/* keyword */
    LIST *list;	/* list of files containing this keyword */
    int count;	/* number of files in the list */
} FLIST;

/* core database entry */
typedef struct
{
    USER *user;		/* user who possesses this file */
    char *filename;	/* the filename */
    char *hash;		/* the md5 hash of the file */
    int size;		/* size of file in bytes */
    LIST *tokens;	/* list of words in the filename */

    /* next 5 entries make up 64 bits */
    unsigned short bitrate;
    unsigned short duration;
    unsigned short frequency;
    unsigned int refcount : 8;	/* how many references to this structure? */
    unsigned int valid : 8;	/* is this a valid file? */
} DATUM;

typedef enum {
    BAN_IP,
    BAN_USER
} ban_t;

typedef struct _ban {
    ban_t type;
    char *target;
    char *setby;
    char *reason;
    time_t when;
} BAN;

typedef void (*list_destroy_t) (void *);

extern char *Motd_Path;
extern char *Db_Host;
extern char *Db_User;
extern char *Db_Pass;
extern char *Db_Name;
extern char *Listen_Addr;
extern char *Server_Name;
extern char *Server_Pass;
extern int Server_Port;
extern int SigCaught;	/* flag to control main loop */
extern int Max_User_Channels;	/* # of channels is a user allowed to join */
extern int Stat_Click;
extern int Server_Queue_Length;
extern int Client_Queue_Length;
extern int Max_Search_Results;
extern int Compression_Level;
extern int Compression_Threshold;
extern int Max_Shared;
extern int Max_Connections;
extern int Nick_Expire;
extern int Check_Expire;
extern int Max_Browse_Result;
extern unsigned int Interface;

extern unsigned int Server_Flags;
#define OPTION_STRICT_CHANNELS	1	/* only mods+ can create channels */

extern char Buf[1024];

extern CONNECTION **Clients;	/* locally connected clients */
extern int Num_Clients;

extern int Num_Files;		/* total number of available files */
extern int Num_Gigs;		/* total size of files available (in kB) */

extern CONNECTION **Servers;	/* peer servers */
extern int Num_Servers;

extern BAN **Ban;
extern int Ban_Size;

extern HASH *Users;
extern HASH *Channels;
extern HASH *Hotlist;
extern HASH *File_Table;
extern HASH *MD5;

extern char *Levels[LEVEL_ELITE + 1];

#define set_tag(b,n) set_val(b+2,n)
#define set_len set_val
void set_val (char *d, unsigned short val);

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
#define MSG_SERVER_WHOWAS		605
#define MSG_CLIENT_SETUSERLEVEL		606
#define MSG_SERVER_UPLOAD_REQUEST	607
#define MSG_CLIENT_UPLOAD_OK		608
#define MSG_CLIENT_KILL			610
#define MSG_CLIENT_NUKE			611	/* not implemented */
#define MSG_CLIENT_BAN			612
#define MSG_CLIENT_ALTER_PORT		613
#define MSG_CLIENT_UNBAN		614
#define MSG_CLIENT_BANLIST		615
#define MSG_SERVER_IP_BANLIST		616
#define MSG_CLIENT_LIST_CHANNELS	617
#define MSG_SERVER_CHANNEL_LIST_END	617
#define MSG_SERVER_CHANNEL_LIST		618
#define MSG_CLIENT_LIMIT		619
#define MSG_SERVER_LIMIT		620
#define MSG_CLIENT_MOTD			621	/* client request for motd */
#define MSG_SERVER_MOTD			621
#define MSG_CLIENT_MUZZLE		622
#define MSG_CLIENT_UNMUZZLE		623
#define MSG_CLIENT_DATA_PORT_ERROR	626
#define MSG_SERVER_DATA_PORT_ERROR	626 /* same as client message */
#define MSG_CLIENT_WALLOP		627
#define MSG_SERVER_WALLOP		627 /* same as client message */
#define MSG_CLIENT_ANNOUNCE		628
#define MSG_SERVER_ANNOUNCE		628 /* same as client message */
#define MSG_SERVER_NICK_BANLIST		629
#define MSG_CLIENT_CHANGE_SPEED		700
#define MSG_CLIENT_CHANGE_PASS		701
#define MSG_CLIENT_CHANGE_EMAIL		702
#define MSG_CLIENT_CHANGE_DATA_PORT	703
#define MSG_CLIENT_PING			751
#define MSG_SERVER_PING			751
#define MSG_CLIENT_PONG			752
#define MSG_SERVER_PONG			752
#define MSG_CLIENT_SERVER_RECONFIG	800
#define MSG_CLIENT_SERVER_VERSION	801
#define MSG_CLIENT_SERVER_CONFIG	810
#define MSG_CLIENT_EMOTE		824
#define MSG_SERVER_NAMES_LIST		825
#define MSG_SERVER_NAMES_LIST_END	830
#define MSG_CLIENT_NAMES_LIST		830

/* non-standard message unique to this server */
#define MSG_CLIENT_QUIT			10000	/* user has quit */
#define MSG_SERVER_LOGIN		10010	/* server login request */
#define MSG_SERVER_LOGIN_ACK		10011	/* server login response */
#define MSG_SERVER_USER_IP		10013	/* ip for user */
#define MSG_SERVER_REGINFO		10014	/* registration info */
#define MSG_CLIENT_CONNECT		10100
#define MSG_CLIENT_DISCONNECT		10101
#define MSG_CLIENT_KILL_SERVER		10110
#define MSG_CLIENT_REMOVE_SERVER	10111
#define MSG_CLIENT_LINKS		10112
#define MSG_SERVER_LINKS		10112
#define MSG_CLIENT_USAGE_STATS		10115	/* server usage stats */
#define MSG_SERVER_USAGE_STATS		10115
#define MSG_SERVER_COMPRESSED_DATA	10200	/* deprecated */
#define MSG_CLIENT_SHARE_FILE		10300	/* generic media type */
#define MSG_SERVER_REMOTE_ERROR		10404	/* send 404 to a remote user */

/* offsets into the row returned for library searches */
#define IDX_NICK	0
#define IDX_FILENAME	1
#define IDX_SIZE	2
#define IDX_MD5		3
#define IDX_BITRATE	4
#define IDX_FREQ	5
#define IDX_LENGTH	6
#define IDX_SPEED	7
#define IDX_SOUNDEX	8
#define IDX_TYPE	9

/* utility routines */
void add_client (CONNECTION *);
void add_random_bytes (char *, int);
void add_server (CONNECTION *);
void *array_add (void *, int *, void *);
void *array_remove (void *, int *, void *);
int bind_interface (int, unsigned int, int);
BUFFER *buffer_append (BUFFER *, BUFFER *);
BUFFER *buffer_consume (BUFFER *, int);
void buffer_free (BUFFER *);
int buffer_group (BUFFER *, int);
int buffer_read (int, BUFFER **);
int buffer_size (BUFFER *);
#if HAVE_LIBZ
BUFFER *buffer_uncompress (z_streamp, BUFFER **);
#endif
int buffer_validate (BUFFER *);
int check_connect_status (int);
void close_db (void);
void complete_connect (CONNECTION *con);
void config (const char *);
void config_defaults (void);
void expand_hex (char *, int);
void fdb_garbage_collect (HASH *);
void finalize_compress (ZIP *);
void free_ban (BAN *);
void free_channel (CHANNEL *);
void free_config (void);
void free_datum (DATUM *);
void free_flist (FLIST *);
void free_hotlist (HOTLIST *);
void free_user (USER *);
void fudge_path (const char *, char *, int);
char *generate_nonce (void);
void init_compress (CONNECTION *, int);
int init_db (void);
void init_random (void);
LIST *list_append (LIST *, void *);
void list_free (LIST *, list_destroy_t);
void log (const char *fmt, ...);
unsigned int lookup_ip (const char *host);
int make_tcp_connection (const char *host, int port, unsigned int *ip);
char *my_ntoa (unsigned int);
USER *new_user (void);
CHANNEL *new_channel (void);
CONNECTION *new_connection (void);
HOTLIST *new_hotlist (void);
int new_tcp_socket (void);
char *next_arg (char **);
void nosuchuser (CONNECTION *, char *);
void notify_mods (const char *, ...);
void part_channel (CHANNEL *, USER *);
void pass_message (CONNECTION *, char *, size_t);
void pass_message_args (CONNECTION * con, unsigned int msgtype,
			const char *fmt, ...);
void permission_denied (CONNECTION *con);
int pop_user (CONNECTION * con, char **pkt, USER ** user);
void queue_data (CONNECTION *, char *, int);
size_t read_bytes (int, char *, size_t);
void remove_connection (CONNECTION *);
void remove_user (CONNECTION *);
void send_cmd (CONNECTION *, unsigned int msgtype, const char *fmt, ...);
int set_keepalive (int, int);
int set_nonblocking (int);
int set_tcp_buffer_len (int, int);
int split_line (char **template, int templatecount, char *pkt);
int send_queued_data (CONNECTION *con);
void sql_error (const char *function, const char *query);
char *strlower (char *);
void synch_server (CONNECTION *);
LIST *tokenize (char *);
int validate_user (USER *);
int validate_channel (CHANNEL *);
int validate_connection (CONNECTION *);
int validate_hotlist (HOTLIST *);

#define HANDLER(f) void f (CONNECTION *con, unsigned short tag, unsigned short len, char *pkt)
/* this is not a real handler, but has the same arguments as one */
HANDLER (dispatch_command);

/* protocol handlers */
HANDLER (add_file);
HANDLER (add_hotlist);
HANDLER (alter_port);
HANDLER (announce);
HANDLER (ban);
HANDLER (banlist);
HANDLER (browse);
HANDLER (change_data_port);
HANDLER (change_email);
HANDLER (change_speed);
HANDLER (change_pass);
HANDLER (client_quit);
HANDLER (compressed_data);
HANDLER (data_port_error);
HANDLER (download);
HANDLER (download_end);
HANDLER (download_start);
HANDLER (emote);
HANDLER (join);
HANDLER (kill_user);
HANDLER (kill_server);
HANDLER (level);
HANDLER (list_channels);
HANDLER (list_users);
HANDLER (login);
HANDLER (muzzle);
HANDLER (nuke_user);
HANDLER (part);
HANDLER (ping);
HANDLER (privmsg);
HANDLER (priv_errmsg);
HANDLER (public);
HANDLER (queue_limit);
HANDLER (reginfo);
HANDLER (register_nick);
HANDLER (remove_file);
HANDLER (remove_hotlist);
HANDLER (remove_server);
HANDLER (resume);
HANDLER (search);
HANDLER (server_config);
HANDLER (server_connect);
HANDLER (server_disconnect);
HANDLER (server_error);
HANDLER (server_links);
HANDLER (server_login);
HANDLER (server_login_ack);
HANDLER (server_reconfig);
HANDLER (server_stats);
HANDLER (server_usage);
HANDLER (server_version);
HANDLER (share_file);
HANDLER (show_motd);
HANDLER (unmuzzle);
HANDLER (upload_ok);
HANDLER (upload_start);
HANDLER (upload_end);
HANDLER (topic);
HANDLER (unban);
HANDLER (upload_request);
HANDLER (user_ip);
HANDLER (user_speed);
HANDLER (wallop);
HANDLER (whois);

#define CHECK_USER_CLASS(f) if (con->class != CLASS_USER) { log ("%s: not USER class", f); return; }
#define CHECK_SERVER_CLASS(f) if(con->class != CLASS_SERVER) { log ("%s: not SERVER class", f); return; }

#define NONULL(p) (p!=0?p:"")

#ifndef HAVE_SOCKLEN_T
#ifdef __sun__
/* solaris 2.6 uses a signed int for the 4th arg to accept() */
typedef int socklen_t;
#else
typedef unsigned int socklen_t;
#endif
#endif

#ifdef __sun__
#define SOCKOPTCAST (char*)
#else
#define SOCKOPTCAST
#endif /* __sun__ */

/*
** Macros to use to aid in porting code to Win32
*/
#ifndef WIN32
#define READ read
#define WRITE write
#define CLOSE close
#else
#define READ(a,b,c) recv(a,b,c,0)
#define WRITE(a,b,c) send(a,b,c,0)
#define CLOSE closesocket
#define EINPROGRESS WSAEINPROGRESS

#define SHAREDIR "/opennap"
#define PACKAGE "opennap"
#define VERSION "0.12"

#define strcasecmp stricmp
#define strncasecmp strnicmp

// see snprintf.c
extern int snprintf (char *str,size_t count,const char *fmt,...);
extern int vsnprintf (char *str, size_t count, const char *fmt, va_list args);

#endif /* !WIN32 */

#endif /* opennap_h */
