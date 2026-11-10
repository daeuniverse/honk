Changed

- XDP devices whose physical MTU plus the maximum Ethernet/VLAN header fits one 4096-byte TX frame use 480 Port bulk frames, 512-entry rings and 256 bulk frames per capture scope. Devices above that bound retain the previous explicit capacities, and TUN retains 128 scope bulk frames. The shared 256 MiB capture budget and per-class service limits are unchanged.
