# hsync

this is a very work-in-progress real-time file syncing program that runs over QUIC and requires almost zero babysitting.  

similar technique to [google's cdc-file-transfer](https://github.com/google/cdc-file-transfer/), uses fastcdc to do content-defined chunking and myers diffing to be able to pass blocks of data over the network when need be without having to shift around blocks.  

what i am focusing on now is ironing out bugs and moving towards a more usable interface and also making it usable over a WAN which is the final goal of this project (to enable hands-free file-syncing in a less-than-ideal environment).  

i am using inotify to track fs events but finagling around caveats is really annoying. for example, this does not work with subfolders because the API itself requires creating additional watches for every subfolder. newer solutions like fanotify exist but they are still somewhat annoying to work with in rust (i will consider this as an option in the near future).  

there's a weird stipulation where changes in a time window under 2 seconds are corrupted. i will eventually come up with something to allow for faster transfers

## stuff to do

- test routines
- get TLS working
- test over network
- add support for subfolders
