# uwsgi-libssh2
*Still a work in progress!*

## Configuration

### ssh-mountpoint
Through the `ssh-mount` flag you can mount an entire SSH remote path as a uwsgi application, by specifying the muountpoint and the ssh-url.

An example, as an .ini configuration entry:

```ini
    ssh-mount = mountpoint=/foo,remote=ssh://username:password@127.0.0.1:2222/tmp
```

### ssh-url specifications
The ssh-mount flag and event the SSH routing options expect, as an argument, an SSH-url, having the following syntax:

```html
    ssh://user:password@host:port/path
```

#### Optional parameters / url formatting
* The "ssh://" initial portion can be safely omitted.
    - `user:password@host:port/path`
* The ":password" url slice can be omitted too, but you should provide an alternative authentication method (public key, ssh-agent or default password).
    - `ssh://user@host:port/path`
* If both the "user" and the "password" parameters are omitted, then the entire url is parsed as the remote host. In this case too, you should provide alternative authentication methods.
    - `ssh://host:port/path`
* Oh and, of course, the port too can be omitted. The system will automatically fallback to the SSH default port (22).
    - `ssh://user:password@host/path`

### Ssh authentication methods
* Plain-text password
* Public key authentication
* SSH-agent
