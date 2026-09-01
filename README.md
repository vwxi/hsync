# hsync

this is a real-time file-syncing program for collaborative programming in instances that require more granular synchronization.

## how to use

### server

```
hsync-server --db [path to database]
```

### client (folder host)

```
hsync-client --addr [server addr] --folder [folder to share] --password [password for folder] (--insecure)
```

if you actually want to try this out i recommend using `--insecure` because the QUIC library used requires certificates signed by an authority (which are somewhat annoying to procure).  

on establishing a new connection, you will be provided with a code to send to other users.

> [!NOTE]
> on debug builds, the code will always be "code" for testing but this will break on multi-tenant setups

### client (joining a folder)

```
hsync-client --addr [server addr] --code [code] --password [password for folder]
```

## how?

similar technique to [google's cdc-file-transfer](https://github.com/google/cdc-file-transfer/), uses fastcdc to do content-defined chunking and myers diffing to be able to pass blocks of data over the network when need be without having to shift around blocks.  
