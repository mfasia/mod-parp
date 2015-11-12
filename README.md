# Overview
A POST/GET parameter parser to enable apache modules to validate form parameter send from client.
Cloned from: http://sourceforge.net/projects/parp/

# Building
1. Update version number `g_revision` in: `httpd_src/modules/parp/mod_parp.c`
2. Update release notes: `doc/CHANGES.txt`
3. Update doc: `doc/index.html`
4. Update release number `Release:` in: `httpd_src/modules/parp/mod_parp.spec`
5. Commit last changes
6. Run `sh package.sh`
7. Run `rpmbuild -ta mod_parp-${version}.tar.gz`

# Distributing
- Upload `mod_parp-${version}-${release}.x86_64.rpm` to http://repo1.metafour.com/yumrepo/centos/7/extras/RPMS/x86_64/
- Upload `mod_parp-${version}-${release}.src.rpm` to http://repo1.metafour.com/yumrepo/centos/7/extras/SRPMS/

# Building PARP form scratch
1. Download httpd to `3thrdparty/`. The Version is defined in `./include.sh`
2. Run scripts:
```
      ./unpack.sh
      ./patch.sh
      ./configure.sh
      ./build.sh
```

