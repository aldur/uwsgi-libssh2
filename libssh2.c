#include <uwsgi.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#if !defined(UWSGI_PLUGIN_API) || UWSGI_PLUGIN_API == 1
// uWSGI < 2.1
time_t uwsgi_parse_http_date(char *date, uint16_t len) {
	struct tm hdtm;

	if (len != 29 && date[3] != ',')
		return 0;

	hdtm.tm_mday = uwsgi_str2_num(date + 5);

	switch (date[8]) {
	case 'J':
		if (date[9] == 'a') {
			hdtm.tm_mon = 0;
			break;
		}

		if (date[9] == 'u') {
			if (date[10] == 'n') {
				hdtm.tm_mon = 5;
				break;
			}

			if (date[10] == 'l') {
				hdtm.tm_mon = 6;
				break;
			}

			return 0;
		}

		return 0;

	case 'F':
		hdtm.tm_mon = 1;
		break;

	case 'M':
		if (date[9] != 'a')
			return 0;

		if (date[10] == 'r') {
			hdtm.tm_mon = 2;
			break;
		}

		if (date[10] == 'y') {
			hdtm.tm_mon = 4;
			break;
		}

		return 0;

	case 'A':
		if (date[10] == 'r') {
			hdtm.tm_mon = 3;
			break;
		}
		if (date[10] == 'g') {
			hdtm.tm_mon = 7;
			break;
		}
		return 0;

	case 'S':
		hdtm.tm_mon = 8;
		break;

	case 'O':
		hdtm.tm_mon = 9;
		break;

	case 'N':
		hdtm.tm_mon = 10;
	break;

	case 'D':
		hdtm.tm_mon = 11;
		break;
	default:
		return 0;
	}

	hdtm.tm_year = uwsgi_str4_num(date + 12) - 1900;

	hdtm.tm_hour = uwsgi_str2_num(date + 17);
	hdtm.tm_min = uwsgi_str2_num(date + 20);
	hdtm.tm_sec = uwsgi_str2_num(date + 23);

	return timegm(&hdtm);
}

#endif

#define SSH_DEFAULT_PORT 22

extern struct uwsgi_server uwsgi;

struct uwsgi_plugin libssh2_plugin;

struct uwsgi_libssh2 {
	int auth_pw;
	int auth_ssh_agent;
	char *username;
	char *password;
	char *public_key_path;
	char *private_key_path;
	char *private_key_passphrase;
	int disable_remote_fingerprint_check;
	char *known_hosts_path;
	int ssh_timeout;
	struct uwsgi_string_list *mountpoints;
} ulibssh2;

struct uwsgi_ssh_mountpoint {
	char *mountpoint;
	char *username;
	char *password;
	char *remote;
	char *path;
	int ssh_agent;
	char *pub_key_path;
	char *priv_key_path;
	char *priv_key_passphrase;
	void *next;  // list of uwsgi_ssh_mountpoints (fallback!)
};

static struct uwsgi_option libssh2_options[] = {
	{"ssh-mime", no_argument, 0, "enable mime detection over SSH sessions", uwsgi_opt_true, &uwsgi.build_mime_dict, UWSGI_OPT_MIME},
	{"ssh-password-auth", no_argument, 0, "enable ssh password authentication (default off)", uwsgi_opt_true, &ulibssh2.auth_pw, 0},
	{"ssh-agent", no_argument, 0, "enable ssh-agent authentication (default off)", uwsgi_opt_true, &ulibssh2.auth_ssh_agent, 0},
	{"ssh-user", required_argument, 0, "username to be used in each ssh session", uwsgi_opt_set_str, &ulibssh2.username, 0},
	{"ssh-password", required_argument, 0, "password to be used in each ssh session", uwsgi_opt_set_str, &ulibssh2.password, 0},
	{"ssh-public-key-path", required_argument, 0, "path of id_rsa.pub file, needed only if not using OpenSSL", uwsgi_opt_set_str, &ulibssh2.public_key_path, 0},
	{"ssh-private-key-path", required_argument, 0, "path of id_rsa file (default ~/.ssh/id_rsa)", uwsgi_opt_set_str, &ulibssh2.private_key_path, 0},
	{"ssh-private-key-passphrase", required_argument, 0, "passphrase to use when decoding the privatekey", uwsgi_opt_set_str, &ulibssh2.private_key_passphrase, 0},
	{"disable-ssh-remote-fingerpint-check", no_argument, 0, "disable remote fingerpint checking (default on)", uwsgi_opt_true, &ulibssh2.disable_remote_fingerprint_check, 0},
	{"ssh-known-hosts-path", required_argument, 0, "path to the ssh known_hosts file (default ~/.ssh/known_hosts)", uwsgi_opt_set_str, &ulibssh2.known_hosts_path, 0},
	{"ssh-timeout", required_argument, 0, "ssh sessions socket timeout (default uwsgi socket timeout)", uwsgi_opt_set_int, &ulibssh2.ssh_timeout, 0},
	{"ssh-mount", required_argument, 0, "virtual mount the specified ssh volume in a uri", uwsgi_opt_add_string_list, &ulibssh2.mountpoints, UWSGI_OPT_MIME},
	UWSGI_END_OF_OPTIONS
};

int uwsgi_ssh_url_parser(char *url, struct uwsgi_ssh_mountpoint **usm) {
	// [ssh://]username[:password]@host:port/path

	if (!url || !(*usm)) {
		return -1;
	}

	if (!memcmp(url, "ssh://", 6)) {
		url += 6;
	}

	// first of all, the remote path
	char *slash = strchr(url, '/');

	if (slash) {
		*slash = 0;
		(*usm)->path = uwsgi_concat2("/", slash + 1);
	} else {
		uwsgi_log("[SSH] malformed ssh url (path)\n");
		return -1;
	}

	// then, the user:password
	char *at = strchr(url, '@');

	if (at) {
		*at = 0;

		char *colon = strchr(url, ':');

		if (colon) {
			*colon = 0;
			(*usm)->password = uwsgi_str(colon + 1);
		} else {
			(*usm)->password = NULL;  // there is no password!
		}
		(*usm)->username = uwsgi_str(url);

		// and eventually, the remote host (ip:port)
		(*usm)->remote = uwsgi_str(at + 1);
	} else {
		(*usm)->remote = uwsgi_str(url);
	}

	return 0;
}

static void uwsgi_ssh_add_mountpoint(char *arg, size_t arg_len) {
	/*
	--ssh-mount
	Required fields:
		mountpoint=/foo,
		remote=ssh://user[:password]@host:port/path,

	Optional fields:
		ssh_agent=1 (actually, anything will be interpreted as true),
		identity=priv_key_path;priv_key_passphrase (passphrase is optional)
		public_identity=pub_key_path (needed only if not using OpenSSL)
	*/

	if (uwsgi_apps_cnt >= uwsgi.max_apps) {
		uwsgi_log("ERROR: you cannot load more than %d apps in a worker\n", uwsgi.max_apps);
		exit(1);
	}

	struct uwsgi_ssh_mountpoint *usm = uwsgi_calloc(sizeof(struct uwsgi_ssh_mountpoint));

	char *remote_url = NULL;
	char *ssh_agent = NULL;
	char *identity = NULL;

	if (uwsgi_kvlist_parse(arg, arg_len, ',', '=',
			"mountpoint", &usm->mountpoint,
			"remote", &remote_url,
			"ssh-agent", &ssh_agent,
			"identity", &identity,
			"public_identity", &usm->pub_key_path,
			NULL)
		){
		uwsgi_log("[SSH] unable to parse ssh mountpoint definition\n");
		goto shutdown;
	}

	if (uwsgi_ssh_url_parser(remote_url, &usm)) {
		uwsgi_error("uwsgi_ssh_add_mountpoint()/uwsgi_ssh_url_parser()");
		goto shutdown;
	}

	if (!usm->mountpoint || !usm->remote) {
		uwsgi_log("[SSH] mount requires a mountpoint and a remote.\n");
		goto shutdown;
	}

	if (ssh_agent) {
		usm->ssh_agent = 1;
	} else {
		usm->ssh_agent = 0;
	}

	if (identity) {
		char* semicolon = strchr(identity, ';');

		if (semicolon) {
			usm->priv_key_passphrase = semicolon + 1;
		} else {
			usm->priv_key_path = identity;
			usm->priv_key_passphrase = "";
		}
		usm->priv_key_path = identity;
	}

	int app_id = uwsgi_get_app_id(NULL, usm->mountpoint, strlen(usm->mountpoint), libssh2_plugin.modifier1);

	if (app_id == -1) {
		time_t now = uwsgi_now();
		uwsgi_log("[SSH] mounting %s%s on %s.\n", usm->remote, usm->path, usm->mountpoint);

		int id = uwsgi_apps_cnt;

		struct uwsgi_app *ua = uwsgi_add_app(
			id,
			libssh2_plugin.modifier1,
			usm->mountpoint,
			strlen(usm->mountpoint),
			NULL,
			NULL
		);

		if (!ua) {
			uwsgi_log("[SSH] unable to mount %s\n", usm->mountpoint);
			goto shutdown;
		}

		// App storage area.
		ua->callable = usm;

		uwsgi_emulate_cow_for_apps(id);

		ua->started_at = now;
		ua->startup_time = uwsgi_now() - now;
		uwsgi_log("[SSH] mountpoint %d (%s) loaded in %d seconds at %s\n",
			id, usm->remote, (int) ua->startup_time, usm->mountpoint);
	} else {
		uwsgi_log("[SSH] adding %s to high availability configuration for mounpoint %s.\n",
			usm->remote, usm->mountpoint);

		struct uwsgi_app *ua = &uwsgi_apps[app_id];
		struct uwsgi_ssh_mountpoint *usm_list = (struct uwsgi_ssh_mountpoint *) ua->callable;

		while (usm_list->next) {
			usm_list = usm_list->next;
		}

		usm_list->next = usm;

		uwsgi_emulate_cow_for_apps(app_id);
	}

	return;

shutdown:
	exit(1);
}

static void uwsgi_ssh_init_apps() {
	struct uwsgi_string_list *usl = ulibssh2.mountpoints;
	while (usl) {
		uwsgi_ssh_add_mountpoint(usl->value, usl->len);
		usl = usl->next;
	}

	return;
}

static int uwsgi_ssh_waitsocket(int socket_fd, LIBSSH2_SESSION *session) {
	int dir = libssh2_session_block_directions(session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
		if (uwsgi.wait_read_hook(socket_fd, ulibssh2.ssh_timeout) < 0) {
			uwsgi_error("uwsgi_ssh_waitsocket()/wait_read_hook()");
			return -1;
		}
	}

	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
		if (uwsgi.wait_write_hook(socket_fd, ulibssh2.ssh_timeout) < 0) {
			uwsgi_error("uwsgi_ssh_waitsocket()/wait_write_hook()");
			return -1;
		}
	}

	return 0;
}

static int uwsgi_ssh_agent_auth(LIBSSH2_SESSION *session, int sock, char* username) {
	LIBSSH2_AGENT *agent = libssh2_agent_init(session);

	if (!agent) {
		uwsgi_error("uwsgi_ssh_agent_auth()/libssh2_agent_init()");
		goto shutdown;
	}

	if (libssh2_agent_connect(agent)) {
		uwsgi_error("uwsgi_ssh_agent_auth()/libssh2_agent_connect()")
		goto shutdown;
	}

	if (libssh2_agent_list_identities(agent)) {
		uwsgi_error("uwsgi_ssh_agent_auth()/libssh2_agent_list_identities()")
		goto shutdown;
	}

	struct libssh2_agent_publickey *identity, *prev_identity = NULL;
	int rc = 0;

	while (1) {
		rc = libssh2_agent_get_identity(agent, &identity, prev_identity);

		if (rc == 1) {
			uwsgi_log("[SSH] agent couldn't continue authentication.\n");
			goto shutdown;
		} else if (rc < 0) {
			uwsgi_error("uwsgi_ssh_agent_auth()/libssh2_agent_get_identity()");
			goto shutdown;
		}

		while ((rc = libssh2_agent_userauth(agent, username, identity)) == LIBSSH2_ERROR_EAGAIN) {
			if (uwsgi_ssh_waitsocket(sock, session)) {
				goto shutdown;
			}
		}

		if (rc) {
			uwsgi_log("[SSH] agent failed authenticating user %s with public key %s. Continuing...\n",
				username, identity->comment);
		} else {
			break;
		}
		prev_identity = identity;
	}

	/* We're authenticated now. */
	libssh2_agent_disconnect(agent);
	libssh2_agent_free(agent);
	return 0;

shutdown:

	libssh2_agent_disconnect(agent);
	libssh2_agent_free(agent);
	return -1;
}

static int uwsgi_init_ssh_session(
	struct uwsgi_ssh_mountpoint *usm,
	int* socket_fd,
	LIBSSH2_SESSION **session) {

	int sock = uwsgi_connect(usm->remote, ulibssh2.ssh_timeout, 1);
	if (sock < 0) {
		uwsgi_error("uwsgi_init_ssh_session()/uwsgi_connect()");
		return 1;
	}

	int rc = libssh2_init(0);
	if (rc) {
		uwsgi_error("uwsgi_init_ssh_session()/libssh2_init()");
		goto shutdown;
	}

	*session = libssh2_session_init();
	if (!session) {
		uwsgi_error("uwsgi_init_ssh_session()/libssh2_session_init()");
		goto shutdown;
	}

	libssh2_session_set_blocking(*session, 0);

	while ((rc = libssh2_session_handshake(*session, sock)) == LIBSSH2_ERROR_EAGAIN) {
		uwsgi_ssh_waitsocket(sock, *session);
	}
	if (rc) {
		uwsgi_error("uwsgi_init_ssh_session()/libssh2_session_handshake()");
		goto shutdown;
	}

	if (!ulibssh2.disable_remote_fingerprint_check) {
		LIBSSH2_KNOWNHOSTS *nh = libssh2_knownhost_init(*session);
		if (!nh) {
			uwsgi_error("uwsgi_init_ssh_session()/libssh2_knownhost_init()");
			goto shutdown;
		}

		if (libssh2_knownhost_readfile(nh, ulibssh2.known_hosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH) < 0) {
			uwsgi_error("uwsgi_init_ssh_session()/libssh2_knownhost_readfile()");
		}

		size_t len;
		int type;
		const char *fingerprint = libssh2_session_hostkey(*session, &len, &type);
		if (!fingerprint) {
			uwsgi_error("uwsgi_init_ssh_session()/libssh2_session_hostkey()");
			libssh2_knownhost_free(nh);
			goto shutdown;
		}

		char *remoteaddr_str = uwsgi_str(usm->remote);
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
			uwsgi_log("[SSH] Remote fingerprint check failed!\n");
			libssh2_knownhost_free(nh);
			goto shutdown;
		}

		libssh2_knownhost_free(nh);
	}

	// If specified, username and password are honored
	if (usm->username && usm->password) {
		while ((rc = libssh2_userauth_password(
					*session,
					usm->username,
					usm->password)
			) == LIBSSH2_ERROR_EAGAIN) {
			uwsgi_ssh_waitsocket(sock, *session);
		}

		if (rc) {
			uwsgi_error("uwsgi_init_ssh_session()/libssh2_userauth_password()");
			goto shutdown;
		} else {
			goto end;
		}

	// Else, let's try the fallback authentication methods:
	} else if (usm->username || ulibssh2.username) {

		// Let's choose which username to use
		char* auth_user = ulibssh2.username;
		if (usm->username) {
			auth_user = usm->username;
		}

		// Password authentication
		if (ulibssh2.auth_pw && ulibssh2.password) {
			while ((rc = libssh2_userauth_password(
						*session,
						auth_user,
						ulibssh2.password)
				) == LIBSSH2_ERROR_EAGAIN) {
				uwsgi_ssh_waitsocket(sock, *session);
			}
			if (rc) {
				uwsgi_error("uwsgi_init_ssh_session()/libssh2_userauth_password()");
				// goto shutdown;
			} else {
				goto end;
			}
		}

		// SSH agent authentication
		if (usm->ssh_agent || ulibssh2.auth_ssh_agent) {
			if (uwsgi_ssh_agent_auth(*session, sock, auth_user)) {
				uwsgi_error("uwsgi_init_ssh_session()/uwsgi_ssh_agent_auth()");
				// goto shutdown;
			} else {
				goto end;
			}
		}

		// Public key authentication
		if ((ulibssh2.private_key_path && ulibssh2.private_key_passphrase) ||
			(usm->priv_key_path && usm->priv_key_passphrase)) {

			char *actual_pubk_path = ulibssh2.public_key_path;
			if (usm->pub_key_path) {
				actual_pubk_path = usm->pub_key_path;
			}

			char *actual_privk_path = ulibssh2.private_key_path;
			if (usm->priv_key_path) {
				actual_privk_path = usm->priv_key_path;
			}

			char *actual_passphrase = ulibssh2.private_key_passphrase;
			if (usm->priv_key_passphrase) {
				actual_passphrase = usm->priv_key_passphrase;
			}

			while ((rc = libssh2_userauth_publickey_fromfile(
						*session,
						auth_user,
						actual_pubk_path,
						actual_privk_path,
						actual_passphrase)
			) == LIBSSH2_ERROR_EAGAIN) {
				uwsgi_ssh_waitsocket(sock, *session);
			}

			if (rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
				uwsgi_log("[SSH] ssh authentication failed (bad passphrase)\n");
				// goto shutdown;
			} else if (rc) {
				uwsgi_error("uwsgi_init_ssh_session()/libssh2_userauth_publickey_fromfile()");
				// goto shutdown;
			} else {
				goto end;
			}
		}
	}


	// If we arrive here, something went wrong.
	uwsgi_log("[SSH] session initialization failed (no authentication method worked)\n");
shutdown:
		close(sock);
		return 1;

end:
	// Otherwise, we're fine!
	*socket_fd = sock;
	return 0;

}

static int uwsgi_ssh_request_file(
	struct wsgi_request *wsgi_req,
	char* filepath,
	struct uwsgi_ssh_mountpoint *usm
	) {

	int sock = -1;
	int return_status = 0;

	LIBSSH2_SESSION *session = NULL;
	if (uwsgi_init_ssh_session(usm, &sock, &session)) {
		uwsgi_log("[SSH] session initialization failed. Is the SSH server up?\n");
		return_status = 500;
		goto shutdown;
	}

	LIBSSH2_SFTP *sftp_session = NULL;
	do {
		sftp_session = libssh2_sftp_init(session);

		if (!sftp_session) {
			if ((libssh2_session_last_errno(session)) == LIBSSH2_ERROR_EAGAIN) {
				if (uwsgi_ssh_waitsocket(sock, session)) {
					return_status = 500;
					goto shutdown;
				}
			} else {
				uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_init()");
				return_status = 500;
				goto shutdown;
			}
		}
	} while (!sftp_session);

	// Request file stats via SFTP
	LIBSSH2_SFTP_ATTRIBUTES file_attrs;
	int rc;
	while ((rc = libssh2_sftp_stat(sftp_session, filepath, &file_attrs)) == LIBSSH2_ERROR_EAGAIN) {
		if (uwsgi_ssh_waitsocket(sock, session)) {
			return_status = 500;
			goto shutdown;
		}
	}

	if (rc < 0) {
		// If it fails, requested file could not exist.
		if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL && libssh2_sftp_last_error(sftp_session) == LIBSSH2_FX_NO_SUCH_FILE) {
				return_status = 404;
		} else {
			uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_stat()");
			return_status = 500;
		}
		goto sftp_shutdown;
	}

	if (wsgi_req->if_modified_since_len) {
		time_t ims = uwsgi_parse_http_date(wsgi_req->if_modified_since, wsgi_req->if_modified_since_len);
		if (file_attrs.mtime <= (unsigned long)ims) {
			if (uwsgi_response_prepare_headers(wsgi_req, "304 Not Modified", 16) || uwsgi_response_write_headers_do(wsgi_req)) {
				uwsgi_error("uwsgi_parse_http_date()/uwsgi_response_prepare_headers(do)()");
			}
			return_status = 500;
			goto sftp_shutdown;
		}
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "200", 3)) {
		uwsgi_error("uwsgi_ssh_request_file()/uwsgi_response_prepare_headers()");
		return_status = 500;
		goto sftp_shutdown;
	}

	if (uwsgi_response_add_content_length(wsgi_req, file_attrs.filesize)) {
		uwsgi_error("uwsgi_ssh_request_file()/uwsgi_response_add_content_length()");
		return_status = 500;
		goto sftp_shutdown;
	}

	if (uwsgi_response_add_last_modified(wsgi_req, file_attrs.mtime)) {
		uwsgi_error("uwsgi_ssh_request_file()/uwsgi_response_add_last_modified()");
		return_status = 500;
		goto sftp_shutdown;
	}

	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(filepath, strlen(filepath), &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) {
			uwsgi_error("uwsgi_ssh_request_file()/uwsgi_response_add_content_type()");
			// goto sftp_shutdown;
		}
	}

	// Request a file via SFTP
	LIBSSH2_SFTP_HANDLE *sftp_handle = NULL;
	do {
		sftp_handle = libssh2_sftp_open(sftp_session, filepath, LIBSSH2_FXF_READ, 0);

		if (!sftp_handle) {
			if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
				uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_open()");
				return_status = 500;
				goto sftp_shutdown;
			} else {
				if (uwsgi_ssh_waitsocket(sock, session)) {
					return_status = 500;
					goto sftp_shutdown;
				}
			}
		}
	} while (!sftp_handle);

	size_t buffer_size = uwsgi.page_size;
	void *buffer = alloca(buffer_size);
	libssh2_uint64_t read_size = 0;

	while (read_size < file_attrs.filesize) {
		rc = libssh2_sftp_read(sftp_handle, buffer, buffer_size);

		if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (uwsgi_ssh_waitsocket(sock, session)) {
				return_status = 500;
				goto sftp_shutdown;
			}
		} else if (rc < 0) {
			uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_read()");
			break;
		} else {
			read_size += rc;
			if (uwsgi_response_write_body_do(wsgi_req, buffer, rc)) {
				uwsgi_error("uwsgi_ssh_request_file()/uwsgi_response_write_body_do()");
				break;
			}
		}
	}

	while ((rc = libssh2_sftp_close(sftp_handle)) == LIBSSH2_ERROR_EAGAIN) {
		if (uwsgi_ssh_waitsocket(sock, session)) {
			return_status = 500;
			goto sftp_shutdown;
		}
	};
	if (rc < 0) {
		uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_close()");
	}

sftp_shutdown:

	while ((rc = libssh2_sftp_shutdown(sftp_session)) == LIBSSH2_ERROR_EAGAIN) {
		uwsgi_ssh_waitsocket(sock, session);
	}
	if (rc < 0) {
		uwsgi_error("uwsgi_ssh_request_file()/libssh2_sftp_shutdown()");
	}

shutdown:

	while (libssh2_session_disconnect(session, "Normal Shutdown, thank you!") == LIBSSH2_ERROR_EAGAIN) {
		uwsgi_ssh_waitsocket(sock, session);
	}
	libssh2_session_free(session);
	close(sock);
	libssh2_exit();
	return return_status;
}

#ifdef UWSGI_ROUTING
static int uwsgi_ssh_routing(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	// ssh://username[:password]@127.0.0.1:2222/tmp/foo.txt,username[:password]@127.0.0.1:2222/tmp/foobis.txt

	char *remote_url = NULL;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
	uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);
	struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
	if (!ub) {
		uwsgi_error("uwsgi_ssh_routing()/uwsgi_routing_translate()");
		remote_url = ur->data;
	} else {
		remote_url = ub->buf;
	}

	remote_url = uwsgi_concat2(remote_url, ",");
	char *remote_pointer = remote_url;
	char *comma = NULL;
	struct uwsgi_ssh_mountpoint *usm = uwsgi_calloc(sizeof(struct uwsgi_ssh_mountpoint));
	int return_status = -1;

	while ((comma = strchr(remote_url, ',')) != NULL) {
		*comma = 0;

		if (uwsgi_ssh_url_parser(remote_url, &usm)) {
			uwsgi_log("[SSH] skipping malformed route %s\n", remote_url);
			return_status = 500;
			continue;
		}

		if (!(return_status = uwsgi_ssh_request_file(
					wsgi_req,
					usm->path,
					usm
		)))
		{
			goto end;
		} else {
			uwsgi_log("[SSH] route %s to %s returned %d. Engaging fail-over mechanism (if any)...\n",
				usm->remote, usm->path, return_status);
		}

		remote_url = comma + 1;
	}

	switch (return_status) {
		case 404:
			uwsgi_404(wsgi_req);
			break;

		case 500:
		default:
			uwsgi_500(wsgi_req);
	}

end:
	free(remote_pointer);
	uwsgi_buffer_destroy(ub);
	return UWSGI_OK;
}

static int ssh_router(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_ssh_routing;

	if (!memcmp(args, "//", 2)) {
		ur->data = args+2;  // skip trailing ssh:// slashes
	} else {
		ur->data = args;
	}

	ur->data_len = strlen(ur->data);
	return 0;
}

static void uwsgi_register_ssh_router(void) {
	uwsgi_register_router("ssh", ssh_router);
}
#endif

static int uwsgi_ssh_request(struct wsgi_request *wsgi_req) {


#if !defined(UWSGI_PLUGIN_API) || UWSGI_PLUGIN_API == 1
	if (!wsgi_req->uh->pktsize)
#else
	if (!wsgi_req->len)
#endif
	{
		uwsgi_log("[SSH] skipping empty request.\n");
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_error("uwsgi_ssh_request()/uwsgi_parse_vars()");
		return -1;
	}

	if (wsgi_req->path_info_len == 0 ||
		wsgi_req->path_info_len > PATH_MAX ||
		wsgi_req->path_info[wsgi_req->path_info_len - 1] == '/') {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, libssh2_plugin.modifier1);

	if (wsgi_req->app_id == -1 && !uwsgi.no_default_app && uwsgi.default_app > -1) {
		if (uwsgi_apps[uwsgi.default_app].modifier1 == libssh2_plugin.modifier1) {
			wsgi_req->app_id = uwsgi.default_app;
		}
	}

	if (wsgi_req->app_id == -1) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];
	struct uwsgi_ssh_mountpoint *usm_list = (struct uwsgi_ssh_mountpoint *) ua->callable;

	char *complete_filepath = NULL;
	char *filepath = NULL;

	if (wsgi_req->path_info_len > ua->mountpoint_len &&
		memcmp(wsgi_req->path_info, ua->mountpoint, ua->mountpoint_len) == 0) {

		filepath = uwsgi_strncopy(
			wsgi_req->path_info + ua->mountpoint_len,
			wsgi_req->path_info_len - ua->mountpoint_len
		);

	} else {
		filepath = uwsgi_strncopy(wsgi_req->path_info, wsgi_req->path_info_len);
	}

	complete_filepath = uwsgi_concat2(usm_list->path, filepath);
	free(filepath);

	int return_status = 500;
	struct uwsgi_ssh_mountpoint *usm = usm_list;

	do {
		return_status = uwsgi_ssh_request_file(
			wsgi_req,
			complete_filepath,
			usm
		);

	} while (return_status == 500 && ((usm = usm->next) != NULL));

	free(complete_filepath);

	switch (return_status) {
		case 404:
			uwsgi_404(wsgi_req);
			break;

		case 500:
		default:
			uwsgi_500(wsgi_req);
	}

	return 0;
}

static int uwsgi_libssh2_init() {
	char *home = getenv("HOME");

	if (!home) {
		uwsgi_error("uwsgi_libssh2_init()/getenv()");
	}

	if (!ulibssh2.mountpoints && !ulibssh2.username) {
		uwsgi_log("[SSH] you need to specify at least a mountpoint or a username!");
	}

	if (ulibssh2.auth_pw && !ulibssh2.password) {
		uwsgi_log("[SSH] password authentication needs a password!");
		exit(1);
	}

	if (!ulibssh2.private_key_path) {
		ulibssh2.private_key_path = uwsgi_concat2(home, "/.ssh/id_rsa");
	}

	if (!ulibssh2.private_key_passphrase) {
		ulibssh2.private_key_passphrase = "";
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
	.modifier1 = 0,
	.options = libssh2_options,
	.init = uwsgi_libssh2_init,
	.init_apps = uwsgi_ssh_init_apps,
	.request = uwsgi_ssh_request,
#ifdef UWSGI_ROUTING
	.on_load = uwsgi_register_ssh_router,
#endif
};
