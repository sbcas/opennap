bin_PROGRAMS=opennap metaserver spyserv spynap
opennap_SOURCES=opennap.h main.c add_file.c db.c search.c \
	motd.c hash.h hash.c privmsg.c browse.c \
	debug.c debug.h login.c whois.c close_db.c free_user.c \
	join.c part.c public.c part_channel.c \
	announce.c kill_user.c remove_connection.c config.c download.c \
	download_ack.c upload_complete.c topic.c muzzle.c unmuzzle.c \
	level.c client_quit.c server_login.c server_connect.c synch.c util.c \
	md5c.c md5.h global.h hotlist.c remove_file.c list_channels.c \
	list_users.c ping.c resume.c change.c
metaserver_SOURCES=metaserver.c
spyserv_SOURCES=spyserv.c
spynap_SOURCES=spynap.c
spynap_LDADD=-lreadline
EXTRA_DIST=sample.conf sample.motd napster.txt .indent.pro create_db.sql FAQ
INCLUDES=-I/usr/include/mysql -DSHAREDIR=\"$(pkgdatadir)\"
