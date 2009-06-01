#!/usr/bin/env python
##

import os

## Move drcom/dromclient.py -> tarball/drcom-pum-1.0/src/python-user-mode/
fd = file('drcom/drcomclient.py','r')
content = fd.read()
fd.close()
content = content.replace('#'*2+' '*9+'drcomclient.py', '#'*2+' '*9+'drcomclient'+' '*2,1)
fd = file('tarball/drcom-pum-1.0/src/python-user-mode/drcomclient','w')
fd.write(content)
fd.close()

## Move scripts/* -> tarball/drcom-pum-1.0/src/scripts/
os.system('cp scripts/* tarball/drcom-pum-1.0/src/scripts/')

## Create debian package
#os.system('sudo dpkg-buildpackage -rfakeroot')
#os.system('sudo rm -rf tarball/drcom-pum-1.0/debian/drcom-pum/')

## Create Source Package


