hypersocket-osx
===============

This project contains the OSX Kernel Extension used by the Hypersocket Client 
to forward packets to the Hypersocket VPN Server.

Installing
==========

After building in Xcode locate the newly built bundle and copy to /Library/Extensions/ as root. Ensure the bundle has the correct ownership and permissions by executing the following commmand.

`chown -R root:wheel RedirectNKE.kext

The kext needs to be signed. If you need to disable signing temporarily to test the Kernel Extension you can execute the following command

`sudo nvram boot-args="kext-dev-mode=1"

And then reboot.

To load the kext

`sudo kextload /Library/Extensions/RedirectNKE.kext

To unload the kext

`sudo kextunload /Library/Extensions/RedirectNKE.kext

Usage
=====
