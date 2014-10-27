# uwsgi-libssh2
A uWSGI plugin for the integration with [libssh2](http://www.libssh2.org/).

This plugin allows you to serve resources located on remote servers by using the SSH2 protocol.
It supports clear-text authentication, public key identity and ssh-agent.

You can specify such resources by using one or more ssh-mountpoints or by using a custom routing rule.

__Note:__ you can use this plugin in both multi-thread and multi-process asynchronous mode.

# Configuration

## ssh-mountpoint
The `ssh-mount` option let you mount an entire SSH remote path as a uWSGI application.
All you need to do is to specify the muountpoint and the ssh-url.

An example, as an .ini configuration entry:

```ini
ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp
```

__Warning:__ if your proxy doesn't set the `SCRIPT_NAME` and `PATH_INFO` fields you have to tell uWSGI to manage the script names:
```ini
manage-script-name = 1
```

### ssh-mountpoint alternative authentication methods
In addition to the standard username/password fields in the ssh-url, you can specify the following alternative [authentication methods](#ssh-authentication-methods).
```ini
; Custom identity: PrivateKeyPath(;Passphrase)
ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp,identity=t/id_rsa.pub;t/id_rsa;secret

; Custom identity with PublicKey 
; (needed only if libssh2 has not been built against OpenSSL)
ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp,identity=t/id_rsa.pub;t/id_rsa;secret,public-identity=t/id_rsa.pub

; SSH-agent:
ssh-mount = mountpoint=/foo,remote=ssh://test@127.0.0.1:2200/mnt/foo,ssh-agent=1
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

__Remember:__ the system will fallback to the other configurations only if the initialization of an SSH session with the previous has failed.
In other words, the high availability will not kick-in if the requested resources are not found on the remote server, but only in case of server or configuration error.

## ssh-url
ssh-mount expects as a parameter an SSH-url, having the following syntax:

```html
ssh://user:password@host:port/path
```

### Optional parameters / url formatting
* The "ssh://" initial portion can be safely omitted.
    - `user:password@host:port/path`
* The ":password" url slice can be omitted too. In this case you should provide an [alternative authentication method](#ssh-authentication-methods) (public key, ssh-agent or default password).
    - `ssh://user@host:port/path`
* If both the "user" and the "password" parameters are omitted, then the entire url is parsed as the remote host. In this case too, you should provide [alternative authentication methods](#ssh-authentication-methods).
    - `ssh://host:port/path`
* Oh and, of course, the port can be omitted. The system will automatically fallback to the SSH default port (22).
    - `ssh://user:password@host/path`

## SSH authentication methods
Clear-text passwords stored in any configuration file are _improper_.

As a consequence, you could set-up several alternative (and better) authentication methods.
These methods will be automatically and globally used if not differently specified in the ssh-url or in the mountpoint configuration.

### Public key authentication
You can specify your identity by using the following options:

```ini
ssh-private-key-path = foo/id_rsa ; default value ~/.ssh/id_rsa
ssh-private-key-passphrase = yourspassphrase ; empty string by default

; If you haven't built libssh2 against OpenSSL you should specify the public key too:
ssh-public-key-path = foo/id_rsa.pub
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
__Remember:__ the user field in the ssh-url overrides this option.

## SSH routing
If you have uWSGI [internal routing enabled](http://uwsgi-docs.readthedocs.org/en/latest/InternalRouting.html) you can define custom ssh routing rules.

```ini
; An image
route = ^/img$ ssh://test:foo@127.0.0.1:2200/tmp/im_so_random.png
```
As you can see you only have to specify the ssh url as destination.

Obviously, we can provide some more complex examples:
```ini
; Fallback by plugin rules
route = ^/foofirst$ ssh://test:foo@127.0.0.1:2200/tmp/foo.txt,test:foo@127.0.0.1:2200/tmp/foobis.txt
; SSH-URL without password (uses default password)
route = ^/footris$ ssh://test@127.0.0.1:2200/tmp/footris.txt
; SSH-URL without user and password (uses default value)
route = ^/foobis$ ssh://127.0.0.1:2200/tmp/foobis.txt
```
If there are network/server problems on `test:foo@127.0.0.1:2200/tmp/foo.txt` the system will automatically fallback to `test:foo@127.0.0.1:2200/tmp/foobis`.txt. The fallback mechanism will be engaged if the HTTP results status is different from 200.

### Routing mountpoints
As a bonus, you can emulate the mountpoint functionality by using the routing rules:
```ini
; Routing + regexp "mountpoint"
route = ^/mp/(.*)$ ssh://test:foo@127.0.0.1:2200/home/foo/$1
```
In this example, each request to /mp/ will be mapped to the correspondent resource in /home/foo/.

## Other options
* `ssh-mime` enables the mime detection of remote resources;
* `disable-ssh-remote-fingerpint-check` disables the check of the remote fingerprint against the local known hosts.
* `ssh-known-hosts-path` let you specify a custom known host file.
* `ssh-timeout` let you specify a custom timeout related to SSH operations.

__Note:__ this plugin does not modify the known hosts file. As a consequence, you should edit it manually or disable the fingeprint check (potentially insecure against MITM attacks).

# Testing
Tests are located in the `t` folder.
In order to run them you should install the `paramiko` and `requests` python modules (you can use pip).

You should first start uWSGI (maybe using the included `example.ini` configuration file).
Then, in another terminal window and from the `t` directory, you can launch the tests with:
```bash
$ python test_uwsgi-libssh2.py
```


