bin_PROGRAMS=opennap metaserver
opennap_SOURCES=opennap.h main.c add_file.c db.c search.c \
	motd.c hash.h hash.c privmsg.c browse.c \
	debug.c debug.h login.c whois.c free_user.c \
	join.c part.c public.c part_channel.c \
	announce.c kill_user.c remove_connection.c config.c download.c \
	upload_complete.c topic.c muzzle.c unmuzzle.c \
	level.c client_quit.c server_login.c server_connect.c synch.c util.c \
	md5c.c md5.h global.h hotlist.c remove_file.c list_channels.c \
	list_users.c ping.c resume.c change.c
opennap_LDADD=-L@MYSQLLIBDIR@ -lmysqlclient
metaserver_SOURCES=metaserver.c
EXTRA_DIST=sample.conf sample.motd napster.txt .indent.pro create_db.sql \
	FAQ patchnap.c spyserv.c spynap.c
INCLUDES=-I@MYSQLINCDIR@ -DSHAREDIR=\"$(pkgdatadir)\"
