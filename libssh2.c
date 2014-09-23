#include <uwsgi.h>
#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int ssh_request_file(const char *hostaddr, uint32_t port, const char *scppath) {
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

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	rc = libssh2_session_handshake(session, sock);
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
	    /* We could authenticate via password */
	    if (libssh2_userauth_password(session, username, password)) {
	        uwsgi_error("Authentication by password failed.");
	        goto shutdown;
	    }
	} else {
	    /* Or by public key */
	    // FIXME
	    if (libssh2_userauth_publickey_fromfile(
		    	session,
		    	username,
		        "/home/username/.ssh/id_rsa.pub",
		        "/home/username/.ssh/id_rsa",
		        password)
	    	)
	    {
	        uwsgi_error("\tAuthentication by public key failed\n");
	        goto shutdown;
	    }
	}

	/* Request a file via SCP */
	LIBSSH2_CHANNEL *channel;
	struct stat fileinfo;
	uwsgi_log("MODE: %d", fileinfo.st_mode);
	channel = libssh2_scp_recv(session, scppath, &fileinfo);
	uwsgi_log("MODE: %d", fileinfo.st_mode);

	if (!channel) {
		uwsgi_error("Unable to open a session");
		goto shutdown;
	}

	off_t got = 0;
    char mem[1024];
	while (got < fileinfo.st_size) {
	    int amount = sizeof(mem);

	    if ((fileinfo.st_size - got) < amount) {
	        amount = fileinfo.st_size - got;
	    }

	    rc = libssh2_channel_read(channel, mem, amount);

	    if (rc > 0) {
	        write(1, mem, rc);
	    }
	    else if (rc < 0) {
	        uwsgi_error("libssh2_channel_read() failed");
	        break;
	    }
	    got += rc;
	}

	libssh2_channel_free(channel);
	channel = NULL;

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
	ssh_request_file(ur->data, port, ur->data3);

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
