Packet Forwarding Kernel Extension for OSX
==========================================

This project contains the OSX Kernel Extension used by the Hypersocket Client 
to forward packets to the Hypersocket VPN Server.

Installing
----------

After building in Xcode locate the newly built bundle and copy to /Library/Extensions/ as root. Ensure the bundle has the correct ownership and permissions by executing the following commmand.

`chown -R root:wheel RedirectNKE.kext`

The kext needs to be signed. If you need to disable signing temporarily to test the Kernel Extension you can execute the following command

`sudo nvram boot-args="kext-dev-mode=1"`

And then reboot.

To load the kext

`sudo kextload /Library/Extensions/RedirectNKE.kext`

To unload the kext

`sudo kextunload /Library/Extensions/RedirectNKE.kext`

Usage
-----

The XCode project also includes a command line program for communicating with the Kernel Extension. To start packet forwarding for a given source address / port use:

`RedirectCMD add <source_addr> <source_port> <dest_addr> <dest_port>`

This will forward any packets received at <source_addr> on <source_port> to the <dest_addr> on <dest_port>. For example:

`RedirectCMD add 10.0.0.1 22 127.0.0.1 10022`

To remove a forwarding simply call:

`RedirectCMD remove <source_addr> <source_port> <dest_addr> <dest_port>`

To configure packet logging in the kext use:

`RedirectCMD log <on|off>`
