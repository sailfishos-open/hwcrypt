%define strip /bin/true
%define __requires_exclude  ^.*$
%define __find_requires     %{nil}
%global debug_package       %{nil}
%define __provides_exclude_from ^.*$

Name:     droid-hwcrypt
Summary:  Android Hardware-based Encrytion Tool 
Version:  1.0.0
Release:  %(date +'%%Y%%m%%d%%H%%M')
License:  Apache-2.0
Source0:  out/hwcrypt

%description
%{summary}

%build
pwd
ls -lh

%install
mkdir -p $RPM_BUILD_ROOT/usr/libexec/droid-hybris/system/bin
cp out/hwcrypt $RPM_BUILD_ROOT/usr/libexec/droid-hybris/system/bin

%files
%defattr(-,root,root,-)
/usr/libexec/droid-hybris/system/bin/hwcrypt
