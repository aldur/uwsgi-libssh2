#include <uwsgi.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);


    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

static int ssh_request_file(
	const char *hostaddr,
	uint32_t port,
	const char *scppath,
	void *file,
	size_t *file_len) {

	int auth_pw = 1;
	const char *username = "vagrant";
	const char *password = "vagrant";

	int rc = libssh2_init(0);
	if (rc) {
	    uwsgi_error("libssh2 initialization failed");
	    exit(1);
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (inet_aton(hostaddr, &(sin.sin_addr)) != 1) {
		uwsgi_error("error on inet_aton");
		exit(1);
	};

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		uwsgi_error("error on socket");
		exit(1);
	}

	if (connect(sock, (struct sockaddr*)(&sin),
	        sizeof(struct sockaddr_in)) != 0) {
	    uwsgi_error("failed to connect!");
	    exit(1);
	}

	/* Create a session instance */
	LIBSSH2_SESSION *session = libssh2_session_init();
	if (!session) {
		uwsgi_error("error on session");
	    exit(1);
	}

	/* Since we have set non-blocking, tell libssh2 we are non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */

	while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
	    uwsgi_error("error on handshake");
	    exit(1);
	}

	/* At this point we havn't yet authenticated.  The first thing to do
	 * is check the hostkey's fingerprint against our known hosts.
	 * Your app may have it hard coded, may go to a file, may present it to the
	 * user, that's your call
	 * TODO: Add fingerprint check!
	 */
	const char *fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (!fingerprint) {
		uwsgi_error("error on fingerprint");
		exit(1);
	}

	// printf("Fingerprint: ");
	// int i = 0;
	// for (i = 0; i < 20; i++) {
	//     printf("%02X ", (unsigned char)fingerprint[i]);
	// }
	// printf("\n");

	if (auth_pw) {
		while ((rc = libssh2_userauth_password(session, username, password)) == LIBSSH2_ERROR_EAGAIN);
	    /* We could authenticate via password */
	    if (rc) {
	        uwsgi_error("Authentication by password failed.");
	        goto shutdown;
	    }
	} else {
	    /* Or by public key */
	    // FIXME: keys path!
	    while ((rc = libssh2_userauth_publickey_fromfile(
		    		session, username,
	                "/home/username/"
	                ".ssh/id_rsa.pub",
	                "/home/username/"
	                ".ssh/id_rsa",
                	password)
	    ) == LIBSSH2_ERROR_EAGAIN);
	    if (rc) {
	        uwsgi_error("\tAuthentication by public key failed\n");
	        goto shutdown;
	    }
	}

	LIBSSH2_SFTP *sftp_session = NULL;
	do {
	    sftp_session = libssh2_sftp_init(session);

	    if (!sftp_session) {
	        if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
	            uwsgi_error("non-blocking init\n");
	            waitsocket(sock, session); /* now we wait */
	        } else {
	            uwsgi_error("Unable to init SFTP session\n");
	            goto shutdown;
	        }
	    }
	} while (!sftp_session);

	/* Request a file via SCP */
	// LIBSSH2_SFTP *sftp_session = libssh2_sftp_init(session);

	// if (!sftp_session) {
	//     fprintf(stderr, "Unable to init SFTP session\n");
	//     goto shutdown;
	// }

	/* Request a file via SFTP */
	LIBSSH2_SFTP_HANDLE *sftp_handle = NULL;
	do {
	    sftp_handle = libssh2_sftp_open(sftp_session, scppath, LIBSSH2_FXF_READ, 0);

	    if (!sftp_handle) {
	        if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
	            uwsgi_error("Unable to open file with SFTP\n");
	            goto shutdown;
	        } else {
	            uwsgi_log("non-blocking open\n");
	            waitsocket(sock, session); /* now we wait */
	        }
	    }
	} while (!sftp_handle);

	size_t buffer_size = 1024;
	void *buffer = uwsgi_malloc(buffer_size);

	size_t f_len = 0;
	void *f = NULL;  // let's start slow!
	do {
		rc = libssh2_sftp_read(sftp_handle, buffer, buffer_size);
		uwsgi_log("%d\n", rc);

		if (rc == LIBSSH2_ERROR_EAGAIN) {
			// uwsgi_log("EAGAIN!");
			waitsocket(sock, session);
		} else if (rc <= 0) {
			// TODO: error checking!
			// We're done here!
		    break;
		} else {
		    f_len += rc;
		    if ((f = realloc(f, f_len)) == NULL) {
		    	uwsgi_error("error on realloc");
		    	exit(1);
		    }
		    memcpy(f + (f_len - rc), buffer, rc);
		}
	} while (1);

	*file_len = f_len;
	file = f;

	uwsgi_log("%s, %d\n", f, f_len);

	libssh2_sftp_close(sftp_handle);
	libssh2_sftp_shutdown(sftp_session);

shutdown:
	libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);

	libssh2_exit();
	return 0;
}

static int request_handler(struct wsgi_request *request) {
	if (uwsgi_parse_vars(request)) {
		uwsgi_error("error parsing request vars");
        exit(1);
    }

	char *s = "Request!";
	size_t len = strlen(s) + 1;

	uwsgi_response_prepare_headers(request, "200 OK", 6);
	uwsgi_response_add_content_length(request, len);
	uwsgi_response_add_content_type(request, "text/html", 9);
	uwsgi_response_write_body_do(request, s, len);

	return 0;
}

#ifdef UWSGI_ROUTING
static int ssh_routing(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	uwsgi_log("Data: %s\n", ur->data);
	uwsgi_log("Data2: %s\n", ur->data2);
	uwsgi_log("Data3: %s\n", ur->data3);

	int port = atoi(ur->data2);

	void *file = NULL;
	size_t size = 0;
	int f = ssh_request_file(ur->data, port, ur->data3, file, &size);
	uwsgi_log("%d", f);

	// uwsgi_log("SSH Request!\n");
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
        	comma = strchr(ur->data2, ',');
        	if (comma) {
        		*comma = 0;
        		ur->data3 = comma + 1;
        		ur->data3_len = strlen(ur->data3);
        	}
        	ur->data2_len = strlen(ur->data2);
        }
        return 0;
}

static void register_ssh_router(void) {
	uwsgi_register_router("ssh", ssh_router);
}
#endif

struct uwsgi_plugin libssh2_plugin = {
    .name = "libssh2",
#ifdef UWSGI_ROUTING
    .on_load = register_ssh_router,
#endif
    .request = request_handler,
};
