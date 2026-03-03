Name:           lochs
Version:        0.3.6
Release:        1%{?dist}
Summary:        FreeBSD jail management for Linux
License:        MIT
URL:            https://lochs.dev
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc make
Recommends:     socat

%description
Lochs is a Docker-like container management CLI for running FreeBSD
jails on Linux. It includes the bsdulator engine for ptrace-based
FreeBSD syscall translation.

Features include jail management, networking, volumes, image registries,
a web dashboard, compose orchestration, ZFS snapshots, and cgroup v2
resource limits.

%prep
%autosetup

%build
make %{?_smp_mflags}

%install
install -D -m 755 bsdulator %{buildroot}%{_bindir}/bsdulator
install -D -m 755 lochs %{buildroot}%{_bindir}/lochs
install -D -m 644 lochs-dashboard.service %{buildroot}%{_unitdir}/lochs-dashboard.service
install -d %{buildroot}%{_docdir}/%{name}
install -m 644 docs/api.md %{buildroot}%{_docdir}/%{name}/
install -m 644 docs/quickstart.md %{buildroot}%{_docdir}/%{name}/
install -m 644 docs/architecture.md %{buildroot}%{_docdir}/%{name}/
install -d %{buildroot}/var/lib/lochs

%post
mkdir -p /var/lib/lochs/{logs,volumes,jails,images}
%systemd_post lochs-dashboard.service

%preun
%systemd_preun lochs-dashboard.service

%postun
%systemd_postun_with_restart lochs-dashboard.service

%files
%license debian/copyright
%{_bindir}/bsdulator
%{_bindir}/lochs
%{_unitdir}/lochs-dashboard.service
%{_docdir}/%{name}/
%dir /var/lib/lochs

%changelog
* Mon Mar 03 2026 Zachary Kleckner <zach@lochs.dev> - 0.3.6-1
- Dashboard: authentication, TLS, network/volume CRUD, build page
- CLI: cp, export/import, push commands
- Engine: /dev emulation, kqueue stubs, signal handling
- Infrastructure: systemd service, API docs
