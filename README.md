# hsync

this is a work-in-progress real-time file syncing program that runs over QUIC and requires almost zero babysitting.  

similar technique to [google's cdc-file-transfer](https://github.com/google/cdc-file-transfer/), uses fastcdc to do content-defined chunking and myers diffing to be able to pass blocks of data over the network when need be without having to shift around blocks.   

the server-client architecture allows for multiple folders to work simultaneously but i am currently working on a hybrid server-client topology where the server can also act as a client. this will be possible with a filesystem built on FUSE.
