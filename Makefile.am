bin_PROGRAMS=opennap metaserver
opennap_SOURCES=opennap.h main.c add_file.c db.c search.c \
	motd.c hash.h hash.c privmsg.c browse.c \
	debug.c debug.h login.c whois.c free_user.c \
	join.c part.c public.c part_channel.c \
	announce.c kill_user.c remove_connection.c config.c download.c \
	upload_complete.c topic.c muzzle.c unmuzzle.c \
	level.c client_quit.c server_login.c server_connect.c synch.c util.c \
	md5.c md5.h hotlist.c remove_file.c list_channels.c \
	list_users.c ping.c resume.c change.c ban.c network.c buffer.c \
	server_usage.c server_links.c init.c handler.c timer.c list.c \
	list.h
opennap_LDADD=-L@MYSQLLIBDIR@ -lmysqlclient
metaserver_SOURCES=metaserver.c
EXTRA_DIST=sample.conf sample.motd napster.txt .indent.pro create_db.sql \
	FAQ patchnap.c spyserv.c opennap.dsw opennap.dsp snprintf.c \
	opennap.opt opennap.plg
INCLUDES=-I@MYSQLINCDIR@ -DSHAREDIR=\"$(pkgdatadir)\"
