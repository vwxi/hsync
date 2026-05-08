# hsync

this is a work-in-progress real-time file syncing program that runs over QUIC and requires almost zero babysitting.  

similar technique to [google's cdc-file-transfer](https://github.com/google/cdc-file-transfer/), uses fastcdc to do content-defined chunking and myers diffing to be able to pass blocks of data over the network when need be without having to shift around blocks.   

## current state

the server stores state for every folder but i am working on having the server only store metadata and serve as a rendezvous for clients to directly send chunks to eachother
