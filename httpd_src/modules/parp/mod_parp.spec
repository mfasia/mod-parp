%define aversion %(rpm -q httpd-devel --qf '%{RPMTAG_VERSION}' | tail -1)
%define rversion 0.00-1M4

Summary: A POST/GET parameter parser to enable apache modules to validate form parameter send from client.
Name: mod_parp
Version: 0.00
Release: 1M4
License: Apache License
Group: System Environment/Daemons
URL: https://github.com/mfasia/mod-parp

Packager: Faqueer Tanvir Ahmed <tanvir@metafour.com>
Vendor: christian liesch, Pascal Buchbinder

Source: http://sourceforge.net/projects/parp/files/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/root-%{name}-%{version}
Prefix: %{_prefix}

BuildRequires: zlib-devel, httpd-devel
Requires: httpd >= %{aversion}

%description
  ____  _____  ____ ____
 |H _ \(____ |/ ___)  _ \
 |T|_| / ___ | |   | |_| |
 |T __/\_____|_|   |  __/
 |P|ParameterParser|_|
 http://parp.sourceforge.net

mod_parp is a HTTP request parameter parser module for the Apache web
server. It processes the request message body as well as the query
portion of the request URL. The module parsed this data and provides
all parameter to other Apache modules by a table of name/value pairs.

For more documentation, see the doc/index.html file.

%prep
%setup -n %{name}-%{version}

%{__cat} <<'EOF' >apache2/mod_parp.conf
# Load the module into your server:
LoadModule parp_module modules/mod_parp.so
<IfModule mod_parp.c>
# activate mod_parp for all requests matching the URL /a /b but not the URL /a/u
pload:
SetEnvIf   Request_URI   ^/a.*            parp
SetEnvIf   Request_URI   ^/a/upload.*    !parp
SetEnvIf   Request_URI   ^/b.*            parp

# suppress content types not supported by mod_parp:
SetEnvIf   Content-Type  text/plain      !parp
SetEnvIf   Content-Type  text/xml        !parp
SetEnvIf   Content-Type  text/html       !parp

# Error handling:
# mod_parp denies request on parsing errors by default. The default
# return code is 500. You may override this return code using the
# directive "PARP_ExitOnError <code>". Set the code to 200 in order to
# ignore erros.
PARP_ExitOnError         200

# Enable processing of other "raw" data types:
PARP_BodyData            text/plain text/xml text/html
SetEnvIf   Content-Type  text/plain       parp
SetEnvIf   Content-Type  text/xml         parp
SetEnvIf   Content-Type  text/html        parp

</IfModule>
EOF

%build
cd apache2
#%{__make} %{?_smp_mflags} APXS="%{_sbindir}/apxs"
%{__make}

%install
cd apache2
%{__rm} -rf %{buildroot}
%{__install} -d -m0755 %{buildroot}%{_libdir}/httpd/modules/ \
                        %{buildroot}%{_sysconfdir}/httpd/conf.d/
%{__install} -m0755 .libs/mod_parp.so %{buildroot}%{_libdir}/httpd/modules/
%{__install} -m0644 mod_parp.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc doc/LICENSE.txt doc/CHANGES.txt doc/index.html
%config(noreplace) %{_sysconfdir}/httpd/conf.d/mod_parp.conf
%{_libdir}/httpd/modules/mod_parp.so

%changelog
* Thu Nov 12 2015 Faqueer Tanvir Ahmed <tanvir@metafour.com> - 0.15.1
- RPM build support. See doc/CHANGES.txt.
