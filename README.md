# uwsgi-libssh2
*Still a work in progress!*

# Configuration

## ssh-mountpoint
The `ssh-mount` option let you mount an entire SSH remote path as a uwsgi application.
All you need to do is to specify the muountpoint and the ssh-url.

An example, as an .ini configuration entry:

```ini
ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp
```

### ssh-mountpoint high availability
You may want to specify different ssh-urls related to the same mountpoint as a fallback mechanism, in case something goes wrong.
In this case, simply postpone your fallback configuration to the principal one.

```ini
; principal configuration
ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp
; fallback #1
ssh-mount = mountpoint=/foo,remote=ssh://username:password@remoteserver/tmp
; fallback #2
; ...
```

Remember: the system will fallback to the other configurations only if the initialization of an SSH session with the previouses has failed.
In other words, the high availability will not kick-in if the requested resources are not found on the remote server, but only in case of server or configuration error.

## ssh-url specifications
The ssh-mount flag and event the SSH routing options expect, as an argument, an SSH-url, having the following syntax:

```html
ssh://user:password@host:port/path
```

### Optional parameters / url formatting
* The "ssh://" initial portion can be safely omitted.
    - `user:password@host:port/path`
* The ":password" url slice can be omitted too. In this case you should provide an [alternative authentication method](#specific-ssh-authentication-methods) (public key, ssh-agent or default password).
    - `ssh://user@host:port/path`
* If both the "user" and the "password" parameters are omitted, then the entire url is parsed as the remote host. In this case too, you should provide [alternative authentication methods](#specific-ssh-authentication-methods).
    - `ssh://host:port/path`
* Oh and, of course, the port can be omitted. The system will automatically fallback to the SSH default port (22).
    - `ssh://user:password@host/path`

## SSH authentication methods
Clear-text passwords stored in any configuration file are _improper_.

As a consequence, you could set-up several alternative (and better) authentication methods.
In case any ssh-url does not contain the password field, these methods will be automatically used.

### Public key authentication
You can specify your identity by using the following options:

```ini
ssh-public-key-path = foo/id_rsa.pub  ; default value ~/.ssh/id_rsa.pub
ssh-private-key-path = foo/id_rsa ; default value ~/.ssh/id_rsa
ssh-private-key-passphrase = yourspassphrase ; empty string by default
```

### SSH-agent
You can enable SSH-agent support by setting in your configuration:

```ini
ssh-agent = 1  ; off by default
```

### Default SSH password
If you're a fan of SSH passwords and you're too lazy to type it in every mountpoint, you can specify a _default_ SSH password:

```ini
ssh-password-auth = 1
ssh-password = weak
```

### Default SSH user

If you need a _default_ SSH user you can set in your INI file:
```ini
ssh-user = foobar
```
Remember: the user field in the ssh-url overrides this option.
