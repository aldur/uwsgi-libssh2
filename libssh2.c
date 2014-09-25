#include <uwsgi.h>
extern struct uwsgi_server uwsgi;

#include <libssh2.h>
#include <libssh2_sftp.h>

#define BUFFER_SIZE 1024
#define USER "vagrant"
#define PASSWORD "vagrant"


static void waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
	int dir = libssh2_session_block_directions(session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
		if (uwsgi.wait_read_hook(socket_fd, uwsgi.socket_timeout) < 0) {
			uwsgi_error("waitsocket()/wait_read_hook()");
		}
	}

	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
		if (uwsgi.wait_write_hook(socket_fd, uwsgi.socket_timeout) < 0) {
			uwsgi_error("waitsocket()/wait_write_hook()");
		}
	}

	return;
}

static int init_ssh_session(char* remoteaddr, int *socket_fd, LIBSSH2_SESSION **session) {
	int auth_pw = 1;
	const char *username = USER;
	const char *password = PASSWORD;

	int sock = uwsgi_connect(remoteaddr, uwsgi.socket_timeout, 1);
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

	// TODO: Check remote fingerprint!
	const char *fingerprint = libssh2_hostkey_hash(*session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (!fingerprint) {
		uwsgi_error("init_ssh_session()/libssh2_hostkey_hash()");
		goto shutdown;
	}

	if (auth_pw) {
		while ((rc = libssh2_userauth_password(*session, username, password)) == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(sock, *session);
		}
		if (rc) {
			uwsgi_error("init_ssh_session()/libssh2_userauth_password()");
			goto shutdown;
		}
	} else {
		// FIXME: keys path!
		while ((rc = libssh2_userauth_publickey_fromfile(
					*session,
					username,
					"/home/username/"
					".ssh/id_rsa.pub",
					"/home/username/"
					".ssh/id_rsa",
					password)
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
	struct uwsgi_route *ur
	) {

	char *remoteaddr = ur->data;
	char *scppath = ur->data2;

	int sock = -1;

	LIBSSH2_SESSION *session = NULL;
	if (init_ssh_session(remoteaddr, &sock, &session)) {
		uwsgi_error("ssh_request_file()/init_ssh_session()");
		goto shutdown;
	}

	LIBSSH2_SFTP *sftp_session = NULL;
	do {
		sftp_session = libssh2_sftp_init(session);

		if (!sftp_session) {
			if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
				waitsocket(sock, session); /* now we wait */
			} else {
				uwsgi_error("ssh_request_file()/libssh2_sftp_init()");
				goto shutdown;
			}
		}
	} while (!sftp_session);

	// Request file stats via SFTP
	LIBSSH2_SFTP_ATTRIBUTES file_attrs;
	int rc;
	while ((rc = libssh2_sftp_stat(sftp_session, scppath, &file_attrs)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	}
	if (rc < 0) {
		uwsgi_error("ssh_request_file()/libssh2_sftp_stat()");
		goto shutdown;
	}

	// TODO: Error codes!
	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_prepare_headers()");
		goto shutdown;
	}

	if (uwsgi_response_add_content_length(wsgi_req, file_attrs.filesize)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_add_content_length()");
		goto shutdown;
	}

	if (uwsgi_response_add_last_modified(wsgi_req, file_attrs.mtime)) {
		uwsgi_error("ssh_request_file()/uwsgi_response_add_last_modified()");
		goto shutdown;
	}

	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(scppath, strlen(scppath), &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) {
			uwsgi_error("ssh_request_file()/uwsgi_response_add_content_type()");
			goto shutdown;
		}
	}

	/* Request a file via SFTP */
	LIBSSH2_SFTP_HANDLE *sftp_handle = NULL;
	do {
		sftp_handle = libssh2_sftp_open(sftp_session, scppath, LIBSSH2_FXF_READ, 0);

		if (!sftp_handle) {
			if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
				uwsgi_error("ssh_request_file()/libssh2_sftp_open()");
				goto shutdown;
			} else {
				waitsocket(sock, session); /* now we wait */
			}
		}
	} while (!sftp_handle);

	size_t buffer_size = BUFFER_SIZE;
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
	if (ssh_request_file(wsgi_req, ur)) {
		uwsgi_error("error while requesting file");
	}

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
	// FIXME: Change me when you have proper options handling
	uwsgi.build_mime_dict = 1;
	uwsgi_register_router("ssh", ssh_router);
}
#endif

struct uwsgi_plugin libssh2_plugin = {
	.name = "libssh2",
#ifdef UWSGI_ROUTING
	.on_load = register_ssh_router,
#endif
	// .request = request_handler,
};
