Summary: open source napster server
Name: opennap
Version: 0.22
Release: 1
Copyright: GPL
Group: System Environment/Daemons
Source: http://opennap.sourceforge.net/downloads/opennap-0.22.tar.gz
BuildRoot: /var/tmp/%{name}-buildroot

%description
opennap is an open source napster server.  napster is a popular protocol for
sharing media files in a distributed fashion.  the server acts as a central
database for searching, and allowing group and private chat.

%prep
%setup
%build
./configure --prefix=/usr
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT
make distclean

%files
%doc AUTHORS FAQ NEWS README COPYING
%dir /usr/share/opennap
%config /usr/share/opennap/servers
%config /usr/share/opennap/users
%config /usr/share/opennap/config
/usr/sbin/opennap
/usr/sbin/metaserver
