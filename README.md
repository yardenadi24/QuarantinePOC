EDR related POC project implemanting the concept of an Quarantine folder.

The fs minifilter once loaded:
Intercept IO related to Directory control
Blocking any attempt to query our quarantine direcroty
and adjusting response for IO to the parent directory, removing the quarantine directory entry so it
wont appear under any search or list.
Intercept IO related to CreateFile to block attempt to open the quarantine directory or even deleting it.



How to run:
1. Compile the project
2. Move the .sys output file to the VM
3. Create the Quarantine directory: C:\EdrPOC\Quarantine
4. In the VM:
   3.1. Run in an elevated cmd: sc create [Service name] type= filesys binPath= [Path to the sys file]
   3.2. Run in an elevated cmd: fltmc load [Service name]
5. Now the path "C:\EdrPOC\Quarantine" is hidden
6. To unload the minifilter:
   6.1 3.2. Run in an elevated cmd: fltmc unload [Service name]
