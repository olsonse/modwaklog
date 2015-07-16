Name:           mod_waklog
Version:        1.1.0
Release:        1%{?dist}
Summary:        Apache module allowing the web server to acquire AFS credentials

Group:          System Environment/Daemons
License:        University of Michigan
Vendor:         Sine Nomine Associates
URL:            http://sourceforge.net/projects/modwaklog/
Source0:        http://sourceforge.net/projects/modwaklog/files/modwaklog/mod_waklog-%{version}.tgz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  openafs-authlibs-devel httpd-devel apr-devel krb5-devel automake
Requires:       httpd

%description
mod_waklog is an Apache module that provides aklog-like semantics
for the web.  mod_waklog will acquire (and store in the kernel) an
AFS credential when a connection is opened, use the credential for
the duration of the connection, and will remove the credential when
the connection is closed.

%prep
%setup -q
# This goes away with a proper dist tarball; likewise BuildRequires: automake
./regen.sh

%build
./configure --libdir=%{_libdir} --with-afs-libs=%{_libdir}/afs
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT%{_libdir}/httpd/modules/
install .libs/mod_waklog.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules/

install -d $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/
install -m 644 waklog.conf $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%{_libdir}/httpd/modules/mod_waklog.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/waklog.conf
%doc README COPYING AUTHORS NEWS

%changelog
* Wed Jul 15 2015 Jacob Welsh <jwelsh@sinenomine.net> - 1.1.0-1
- Initial RPM package
