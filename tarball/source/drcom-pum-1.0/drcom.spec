Name:		drcom-pum          
Version:	1.0       
#Release:        1%{?dist}
Summary:	fully GUI configurable X drcom-client using GTK+        

Group:		Applications/Internet      
License:	GPL     
URL:		http://www.drcom-client.org/    
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	kernel-devel >= 2.6.24, gcc, make, bash
Requires:       python >= 2.4, pygtk2 >= 2.12, notify-python

%description
drcom-client is an open source ISP client for Dr.COM networks, used in 
many universities in China.
drcom-client pum is a branch of drcom-client for Linux development.
It is a fully GUI configurable X drcom-client for Linux, written from
scratch in pure Python. It uses the GTK+ toolkit for all of its 
interface needs. drcom-client pum provides 100% GUI configurability; 
no need to edit config files by hand and re-start the program. 

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%post
/usr/bin/drcom start
/usr/bin/drunlevel add drcom

#%postun
#/usr/bin/drcom stop
#/usr/bin/drunlevel del drcom

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc
/etc/init.d/drcom
/usr/bin/drcom
/usr/bin/drcomclient
/usr/bin/drunlevel
/usr/bin/mkdrcom
/usr/share/applications/drcom.desktop
/usr/share/drcom/resource/COPYING
/usr/share/drcom/resource/drcom.png
/usr/share/drcom/resource/drcom.wav
/usr/share/drcom/resource/po/zh_CN/LC_MESSAGES/drcom.mo
/usr/share/drcom/src/kmod/Makefile
/usr/share/drcom/src/kmod/daemon_kernel.h
/usr/share/drcom/src/kmod/drcom.c
/usr/share/drcom/src/python-user-mode/drcomclient

%changelog
