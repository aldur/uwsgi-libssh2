#include <uwsgi.h>
extern struct uwsgi_server uwsgi;

#include <libssh2.h>
#include <libssh2_sftp.h>

#define SSH_DEFAULT_PORT 22

struct uwsgi_libssh2 {
	int auth_pw;
	char *username;
	char *password;
	char *public_key_path;
	char *private_key_path;
	char *private_key_passphrase;
	int check_remote_fingerpint;
	char *known_hosts_path;
	int ssh_timeout;
} ulibssh2;

static struct uwsgi_option libssh2_options[] = {
	{"ssh-mime", no_argument, 0, "enable mime detection over SSH sessions", uwsgi_opt_true, &uwsgi.build_mime_dict, UWSGI_OPT_MIME},
	{"ssh-password-auth", no_argument, 0, "enable ssh password authentication (default off)", uwsgi_opt_true, &ulibssh2.auth_pw, 0},
	{"ssh-user", required_argument, 0, "username to be used in each ssh session", uwsgi_opt_set_str, &ulibssh2.username, 0},
	{"ssh-password", required_argument, 0, "password to be used in each ssh session", uwsgi_opt_set_str, &ulibssh2.password, 0},
	{"ssh-public-key-path", required_argument, 0, "path of id_rsa.pub file (default ~/.ssh/id_rsa.pub)", uwsgi_opt_set_str, &ulibssh2.public_key_path, 0},
	{"ssh-private-key-path", required_argument, 0, "path of id_rsa file (default ~/.ssh/id_rsa)", uwsgi_opt_set_str, &ulibssh2.private_key_path, 0},
	{"ssh-private-key-passphrase", required_argument, 0, "passphrase to use when decoding the privatekey", uwsgi_opt_set_str, &ulibssh2.private_key_passphrase, 0},
	{"ssh-check-remote-fingerpint", no_argument, 0, "enable remote fingerpint checking (default on)", uwsgi_opt_true, &ulibssh2.check_remote_fingerpint, 0},
	{"ssh-known-hosts-path", required_argument, 0, "path to the ssh known_hosts file (default ~/.ssh/known_hosts)", uwsgi_opt_set_str, &ulibssh2.known_hosts_path, 0},
	{"ssh-timeout", required_argument, 0, "ssh sessions socket timeout (default uwsgi socket timeout)", uwsgi_opt_set_int, &ulibssh2.ssh_timeout, 0},
	UWSGI_END_OF_OPTIONS
};

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
	int dir = libssh2_session_block_directions(session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
		if (uwsgi.wait_read_hook(socket_fd, ulibssh2.ssh_timeout) < 0) {
			uwsgi_error("waitsocket()/wait_read_hook()");
			return -1;
		}
	}

	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
		if (uwsgi.wait_write_hook(socket_fd, ulibssh2.ssh_timeout) < 0) {
			uwsgi_error("waitsocket()/wait_write_hook()");
			return -1;
		}
	}

	return 0;
}

static int init_ssh_session(char* remoteaddr, int *socket_fd, LIBSSH2_SESSION **session) {
	int sock = uwsgi_connect(remoteaddr, ulibssh2.ssh_timeout, 1);
	if (sock < 0) {
		uwsgi_error("init_ssh_session()/uwsgi_connect()");
		return 1;
	}

	int rc = libssh2_init(0);
	if (rc) {
		uwsgi_error("init_ssh_session()/libssh2_init()");
		goto shutdown;
	}

	*session = libssh2_session_init();
	if (!session) {
		uwsgi_error("init_ssh_session()/libssh2_session_init()");
		goto shutdown;
	}

	libssh2_session_set_blocking(*session, 0);

	while ((rc = libssh2_session_handshake(*session, sock)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, *session);
	}
	if (rc) {
		uwsgi_error("init_ssh_session()/libssh2_session_handshake()");
		goto shutdown;
	}

	if (ulibssh2.check_remote_fingerpint) {
		LIBSSH2_KNOWNHOSTS *nh = libssh2_knownhost_init(*session);
		if (!nh) {
			uwsgi_error("init_ssh_session()/libssh2_knownhost_init()");
			goto shutdown;
		}

		if (libssh2_knownhost_readfile(nh, ulibssh2.known_hosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH) < 0) {
			uwsgi_error("init_ssh_session()/libssh2_knownhost_readfile()");
		}

		size_t len;
		int type;
		const char *fingerprint = libssh2_session_hostkey(*session, &len, &type);
		if (!fingerprint) {
			uwsgi_error("init_ssh_session()/libssh2_session_hostkey()");
			libssh2_knownhost_free(nh);
			goto shutdown;
		}

		char *remoteaddr_str = uwsgi_str(remoteaddr);
		char *port_str = strchr(remoteaddr_str, ':');
		int port = SSH_DEFAULT_PORT;

		if (port_str) {
			port_str[0] = 0;
			port_str++;
			port = atoi(port_str);
		}

		struct libssh2_knownhost *host;
		int check = libssh2_knownhost_checkp(
			nh,
			remoteaddr_str,
			port,
			fingerprint,
			len,
			LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW,
			&host
		);

		free(remoteaddr_str);

		if (check != LIBSSH2_KNOWNHOST_CHECK_MATCH) {
			uwsgi_log("Remote fingerprint check failed!\n");
			libssh2_knownhost_free(nh);
			goto shutdown;
		}

		libssh2_knownhost_free(nh);
	}

	if (ulibssh2.auth_pw) {
		while ((rc = libssh2_userauth_password(*session, ulibssh2.username, ulibssh2.password)) == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(sock, *session);
		}
		if (rc) {
			uwsgi_error("init_ssh_session()/libssh2_userauth_password()");
			goto shutdown;
		}
	} else {
		while ((rc = libssh2_userauth_publickey_fromfile(
					*session,
					ulibssh2.username,
					ulibssh2.public_key_path,
					ulibssh2.private_key_path,
					ulibssh2.private_key_passphrase)
		) == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(sock, *session);
		}
		if (rc) {
			uwsgi_error("init_ssh_session()/libssh2_userauth_publickey_fromfile()");
			goto shutdown;
		}
	}

	*socket_fd = sock;
	return 0;

shutdown:
	close(sock);
	return 1;
}

static int ssh_request_file(
	struct wsgi_request *wsgi_req,
	char* remoteaddr,
	char* filepath
	) {

	int sock = -1;

	LIBSSH2_SESSION *session = NULL;
	if (init_ssh_session(remoteaddr, &sock, &session)) {
		uwsgi_log("SSH session initialization failed.\n");
		// uwsgi_error("ssh_request_file()/init_ssh_session()");
		goto shutdown;
	}

	LIBSSH2_SFTP *sftp_session = NULL;
	do {
		sftp_session = libssh2_sftp_init(session);

		if (!sftp_session) {
			if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
				waitsocket(sock, session);
			} else {
				uwsgi_error("ssh_request_file()/libssh2_sftp_init()");
				goto shutdown;
			}
		}
	} while (!sftp_session);

	// Request file stats via SFTP
	LIBSSH2_SFTP_ATTRIBUTES file_attrs;
	int rc;
	while ((rc = libssh2_sftp_stat(sftp_session, filepath, &file_attrs)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	}

	if (rc < 0) {
		// If it fails, requested file could not exist.
		if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL) {
			if (libssh2_sftp_last_error(sftp_session) == LIBSSH2_FX_NO_SUCH_FILE) {
				uwsgi_404(wsgi_req);
			}
			goto sftp_shutdown;
		} else {
			uwsgi_error("ssh_request_file()/libssh2_sftp_stat()");
			uwsgi_500(wsgi_req);
		}
		goto sftp_shutdown;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "200", 3)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_prepare_headers()");
		goto sftp_shutdown;
	}

	if (uwsgi_response_add_content_length(wsgi_req, file_attrs.filesize)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_add_content_length()");
		goto sftp_shutdown;
	}

	if (uwsgi_response_add_last_modified(wsgi_req, file_attrs.mtime)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_add_last_modified()");
		goto sftp_shutdown;
	}

	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(filepath, strlen(filepath), &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) {
			uwsgi_error("ssh_request_file()/uwsgi_response_add_content_type()");
			// goto sftp_shutdown;
		}
	}

	// Request a file via SFTP
	LIBSSH2_SFTP_HANDLE *sftp_handle = NULL;
	do {
		sftp_handle = libssh2_sftp_open(sftp_session, filepath, LIBSSH2_FXF_READ, 0);

		if (!sftp_handle) {
			if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
				uwsgi_error("ssh_request_file()/libssh2_sftp_open()");
				goto sftp_shutdown;
			} else {
				waitsocket(sock, session);
			}
		}
	} while (!sftp_handle);

	size_t buffer_size = uwsgi.page_size;
	void *buffer = alloca(buffer_size);
	libssh2_uint64_t read_size = 0;

	while (read_size < file_attrs.filesize) {
		rc = libssh2_sftp_read(sftp_handle, buffer, buffer_size);

		if (rc == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(sock, session);
		} else if (rc < 0) {
			uwsgi_error("ssh_request_file()/libssh2_sftp_read()");
			break;
		} else {
			read_size += rc;
			if (uwsgi_response_write_body_do(wsgi_req, buffer, rc)) {
				uwsgi_error("ssh_request_file()/uwsgi_response_write_body_do()");
				break;
			}
		}
	}

	while ((rc = libssh2_sftp_close(sftp_handle)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	};
	if (rc < 0) {
		uwsgi_error("ssh_request_file()/libssh2_sftp_close()");
	}

sftp_shutdown:
	while ((rc = libssh2_sftp_shutdown(sftp_session)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	};
	if (rc < 0) {
		uwsgi_error("ssh_request_file()/libssh2_sftp_shutdown()");
	}

shutdown:
	while (libssh2_session_disconnect(session, "Normal Shutdown, thank you!") == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	}
	libssh2_session_free(session);
	close(sock);
	libssh2_exit();
	return 0;
}

#ifdef UWSGI_ROUTING
static int ssh_routing(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	char *remoteaddr = ur->data;
	char *filepath = ur->data2;

	ssh_request_file(wsgi_req, remoteaddr, filepath);
	return 0;
}

static int ssh_router(struct uwsgi_route *ur, char *args) {
	ur->func = ssh_routing;
	ur->data = args;
	ur->data_len = strlen(args);

	char *comma = strchr(ur->data, ',');
	if (comma) {
		*comma = 0;
		ur->data_len = strlen(ur->data);
		ur->data2 = comma + 1;
		ur->data2_len = strlen(ur->data2);
	}
	return 0;
}

static void register_ssh_router(void) {
	uwsgi_register_router("ssh", ssh_router);
}
#endif

static int ssh_request(struct wsgi_request *wsgi_req) {
	if (!wsgi_req->len) {
		uwsgi_log("Empty request. Skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_error("ssh_request()/uwsgi_parse_vars()");
		return -1;
	}

	// TODO: add SSH mirroring?
	char *remoteaddr= "127.0.0.1:2222";
	char *filepath = uwsgi_strncopy(wsgi_req->path_info, wsgi_req->path_info_len);

	ssh_request_file(wsgi_req, remoteaddr, filepath);

	free(filepath);
	return 0;
}

static int uwsgi_libssh2_init() {
	char *home = getenv("HOME");

	if (!home) {
		uwsgi_error("uwsgi_libssh2_init()/getenv()");
	}

	if (!ulibssh2.username) {
		uwsgi_log("SSH authentication needs a username!");
		exit(1);
	}

	if (ulibssh2.auth_pw && !ulibssh2.password) {
		uwsgi_log("SSH password authentication needs a password!");
		exit(1);
	}

	if (!ulibssh2.private_key_path) {
		ulibssh2.private_key_path = uwsgi_concat2(home, "/.ssh/id_rsa");
	}

	if (!ulibssh2.public_key_path) {
		ulibssh2.public_key_path = uwsgi_concat2(home, "/.ssh/id_rsa.pub");
	}

	if (!ulibssh2.private_key_passphrase) {
		ulibssh2.private_key_passphrase = "";
	}

	if (!ulibssh2.check_remote_fingerpint) {
		ulibssh2.check_remote_fingerpint = 1;
	}

	if (!ulibssh2.known_hosts_path) {
		ulibssh2.known_hosts_path = uwsgi_concat2(home, "/.ssh/known_hosts");
	}

	if (!ulibssh2.ssh_timeout) {
		ulibssh2.ssh_timeout = uwsgi.socket_timeout;
	}

	return 0;
}

struct uwsgi_plugin libssh2_plugin = {
	.name = "libssh2",
	.options = libssh2_options,
	.init = uwsgi_libssh2_init,
	.request = ssh_request,
#ifdef UWSGI_ROUTING
	.on_load = register_ssh_router,
#endif
};
