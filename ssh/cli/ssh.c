/*
 * crown-ssh: a small SSH client built on libssh2 with the crown crypto
 * backend. It exists to exercise the backend end to end: key exchange,
 * host key verification, authentication and session channels all run
 * through crown primitives.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <libssh2.h>

#include "crown.h"

#define DEFAULT_PORT 22

static void die(const char *msg) {
    fprintf(stderr, "crown-ssh: %s\n", msg);
    exit(1);
}

static void die_session(const char *msg, LIBSSH2_SESSION *session) {
    char *errmsg = NULL;
    int err = libssh2_session_last_error(session, &errmsg, NULL, 0);
    fprintf(stderr, "crown-ssh: %s: (%d) %s\n", msg, err, errmsg ? errmsg : "unknown error");
    exit(1);
}

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char port_str[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if(getaddrinfo(host, port_str, &hints, &res)) {
        fprintf(stderr, "crown-ssh: cannot resolve %s\n", host);
        return -1;
    }

    for(ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if(fd < 0)
            continue;
        if(!connect(fd, ai->ai_addr, ai->ai_addrlen))
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void read_password(const char *prompt, char *buf, size_t len) {
    struct termios old;
    struct termios no_echo;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if(tcgetattr(STDIN_FILENO, &old) == 0) {
        no_echo = old;
        no_echo.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);
    }
    if(!fgets(buf, (int)len, stdin))
        buf[0] = '\0';
    if(tcgetattr(STDIN_FILENO, &old) == 0)
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    buf[strcspn(buf, "\r\n")] = '\0';
}

/*
 * Host key fingerprint (SHA256, base64, as ssh-keygen -lf prints it), using
 * crown's hash through the C ABI.
 */
static void print_hostkey_fingerprint(LIBSSH2_SESSION *session) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t key_len = 0;
    int key_type = 0;
    const char *key = libssh2_session_hostkey(session, &key_len, &key_type);
    struct Hash *hash;
    unsigned char digest[32];
    char out[64];
    size_t i;
    size_t o = 0;

    if(!key)
        return;

    hash = hash_new_sha256();
    if(!hash)
        return;
    if(hash_write(hash, (const uint8_t *)key, key_len) != (int)key_len ||
       hash_sum(hash, digest, sizeof(digest)) <= 0) {
        hash_free(hash);
        return;
    }
    hash_free(hash);

    for(i = 0; i + 2 < sizeof(digest); i += 3) {
        unsigned int v = (unsigned int)digest[i] << 16 |
                         (unsigned int)digest[i + 1] << 8 |
                         (unsigned int)digest[i + 2];
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
        out[o++] = b64[v & 63];
    }
    if(i < sizeof(digest)) {
        unsigned int v = (unsigned int)digest[i] << 16;
        if(i + 1 < sizeof(digest))
            v |= (unsigned int)digest[i + 1] << 8;
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = i + 1 < sizeof(digest) ? b64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';

    fprintf(stderr, "crown-ssh: host key type %d, SHA256:%s\n", key_type, out);
}

/* Identity files tried when -i is not given. */
static const char *default_identity(int index, char *expanded, size_t size) {
    static const char *names[] = {
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".ssh/id_rsa"
    };
    const char *home = getenv("HOME");

    if(!home || index < 0 || index >= 3)
        return NULL;
    snprintf(expanded, size, "%s/%s", home, names[index]);
    return expanded;
}

static int authenticate(LIBSSH2_SESSION *session, const char *user, const char *identity_file) {
    char expanded[512];
    char password[256];
    int tried = 0;
    int i;

    for(i = -1; i < 3; i++) {
        const char *key;

        if(i < 0) {
            if(!identity_file)
                continue;
            key = identity_file;
        } else {
            if(identity_file)
                break;
            key = default_identity(i, expanded, sizeof(expanded));
            if(!key)
                continue;
        }

        if(access(key, R_OK))
            continue;
        tried++;
        if(!libssh2_userauth_publickey_fromfile(session, user, NULL, key, NULL)) {
            fprintf(stderr, "crown-ssh: authenticated with %s\n", key);
            return 0;
        }
        fprintf(stderr, "crown-ssh: public key %s rejected, trying next\n", key);
    }

    if(!tried)
        fprintf(stderr, "crown-ssh: no usable identity file\n");

    read_password("crown-ssh: password: ", password, sizeof(password));
    if(libssh2_userauth_password(session, user, password)) {
        char *errmsg = NULL;
        libssh2_session_last_error(session, &errmsg, NULL, 0);
        fprintf(stderr, "crown-ssh: password authentication failed: %s\n", errmsg ? errmsg : "unknown error");
        return -1;
    }
    fprintf(stderr, "crown-ssh: authenticated with password\n");
    return 0;
}

static int run_command(LIBSSH2_SESSION *session, const char *command) {
    LIBSSH2_CHANNEL *channel;
    char buf[4096];
    ssize_t n;
    int exit_status = 0;

    channel = libssh2_channel_open_session(session);
    if(!channel) {
        die_session("unable to open channel", session);
        return -1;
    }

    if(libssh2_channel_exec(channel, command)) {
        die_session("unable to execute command", session);
        return -1;
    }

    for(;;) {
        n = libssh2_channel_read(channel, buf, sizeof(buf));
        if(n > 0) {
            if(fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
                break;
            continue;
        }
        if(n == LIBSSH2_ERROR_EAGAIN)
            continue;
        break;
    }

    while((n = libssh2_channel_read_stderr(channel, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stderr);

    libssh2_channel_close(channel);
    exit_status = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    return exit_status;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [-v] [-p port] [-i identity_file] [-l user] "
            "[-c cipher] [-k kex] [-H hostkey] [-m mac] user@host [command]\n",
            argv0);
    exit(1);
}

int main(int argc, char **argv) {
    const char *identity = NULL;
    const char *user = NULL;
    const char *host = NULL;
    const char *command = NULL;
    const char *cipher = NULL;
    const char *kex = NULL;
    const char *hostkey = NULL;
    const char *mac = NULL;
    char *user_host = NULL;
    int port = DEFAULT_PORT;
    int verbose = 0;
    int fd;
    int ret;
    int c;
    LIBSSH2_SESSION *session;

    while((c = getopt(argc, argv, "vp:i:l:c:k:H:m:h")) != -1) {
        switch(c) {
            case 'v':
                verbose = 1;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'i':
                identity = optarg;
                break;
            case 'l':
                user = optarg;
                break;
            case 'c':
                cipher = optarg;
                break;
            case 'k':
                kex = optarg;
                break;
            case 'H':
                hostkey = optarg;
                break;
            case 'm':
                mac = optarg;
                break;
            default:
                usage(argv[0]);
        }
    }

    if(optind >= argc)
        usage(argv[0]);

    user_host = argv[optind++];
    if(optind < argc)
        command = argv[optind];

    if(!user) {
        char *at = strchr(user_host, '@');
        if(!at)
            usage(argv[0]);
        *at = '\0';
        user = user_host;
        host = at + 1;
    } else {
        host = user_host;
    }

    if(verbose) {
        fprintf(stderr, "crown-ssh: libssh2 %s\n", libssh2_version(0));
        fprintf(stderr, "crown-ssh: crypto backend: %s\n", libssh2_crypto_engine() == libssh2_crown ? "Crown" : "not Crown");
    }

    if(libssh2_init(0))
        die("libssh2_init failed");

    fd = tcp_connect(host, port);
    if(fd < 0) {
        fprintf(stderr, "crown-ssh: cannot connect to %s:%d\n", host, port);
        return 1;
    }

    session = libssh2_session_init();
    if(!session)
        die("cannot create session");

    libssh2_session_set_blocking(session, 1);

#ifdef LIBSSH2DEBUG
    if(verbose)
        libssh2_trace(session, ~0);
#endif

    if(cipher) {
        if(libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_CS, cipher) ||
           libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_SC, cipher))
            die("cannot set cipher preference");
    }
    if(kex && libssh2_session_method_pref(session, LIBSSH2_METHOD_KEX, kex))
        die("cannot set kex preference");
    if(hostkey &&
       libssh2_session_method_pref(session, LIBSSH2_METHOD_HOSTKEY, hostkey))
        die("cannot set hostkey preference");
    if(mac &&
       (libssh2_session_method_pref(session, LIBSSH2_METHOD_MAC_CS, mac) ||
        libssh2_session_method_pref(session, LIBSSH2_METHOD_MAC_SC, mac)))
        die("cannot set mac preference");

    if(libssh2_session_handshake(session, fd))
        die_session("handshake failed", session);

    print_hostkey_fingerprint(session);

    if(verbose) {
        const char *methods = libssh2_session_methods(session, LIBSSH2_METHOD_KEX);
        fprintf(stderr, "crown-ssh: negotiated kex: %s\n", methods ? methods : "?");
        methods = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_CS);
        fprintf(stderr, "crown-ssh: negotiated cipher: %s\n", methods ? methods : "?");
        methods = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_CS);
        fprintf(stderr, "crown-ssh: negotiated mac: %s\n", methods ? methods : "?");
        methods = libssh2_session_methods(session, LIBSSH2_METHOD_HOSTKEY);
        fprintf(stderr, "crown-ssh: hostkey algorithm: %s\n", methods ? methods : "?");
    }

    if(authenticate(session, user, identity)) {
        libssh2_session_disconnect(session, "authentication failed");
        libssh2_session_free(session);
        close(fd);
        return 1;
    }

    if(command)
        ret = run_command(session, command);
    else
        ret = run_command(session, "$SHELL -i");

    libssh2_session_disconnect(session, "bye");
    libssh2_session_free(session);
    close(fd);
    libssh2_exit();

    return ret;
}
