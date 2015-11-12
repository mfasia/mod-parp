# Overview
A POST/GET parameter parser to enable apache modules to validate form parameter send from client.
Cloned from: http://sourceforge.net/projects/parp/

# License
```
 ____  _____  ____ ____  
|H _ \(____ |/ ___)  _ \ 
|T|_| / ___ | |   | |_| |
|T __/\_____|_|   |  __/ 
|P|ParameterParser|_|    
http://parp.sourceforge.net

Copyright (C) 2008-2014 Christian Liesch / Pascal Buchbinder / Lukas Funk

Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. 
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

```

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

