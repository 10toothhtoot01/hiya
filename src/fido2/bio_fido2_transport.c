/*
 * bio_fido2_transport.c — CTAP2 Unix Domain Socket Transport Layer
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides a Unix socket transport for local CTAP2 communication.
 * Browsers and clients connect to /run/bioauth/fido2.sock and exchange
 * framed CTAP2 messages.
 *
 * Wire format (each direction):
 *   ┌──────┬────────────┬──────────┐
 *   │ CMD  │ PAYLOAD_LEN│ PAYLOAD  │
 *   │ 1 B  │ 2 B (BE)   │ N bytes  │
 *   └──────┴────────────┴──────────┘
 *
 *   - Request:  CMD = CTAP2 command byte, PAYLOAD = CBOR request
 *   - Response: CMD = CTAP2 status byte,  PAYLOAD = CBOR response
 *
 * References:
 *   FIDO CTAP 2.1 §11 (Transport-specific Bindings)
 */

#include "fido2/bio_fido2.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/select.h>
#include <poll.h>
#include <grp.h>
#include <pwd.h>

#define BIO_FIDO2_CLIENT_TIMEOUT_SEC 5
#define BIO_FIDO2_MAX_REQUESTS_PER_CLIENT 8

/* ── Internal: Frame I/O ─────────────────────────────────────── */

/*
 * Read exactly `len` bytes from fd into buf.
 * Returns 0 on success, -1 on error/EOF.
 */
static int read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len)
    {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && errno == EAGAIN)
            {
                struct pollfd pfd = {.fd = fd, .events = POLLIN};
                int pr = poll(&pfd, 1, 30000); /* 30s timeout */
                if (pr <= 0)
                    return -1; /* timeout or error */
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/*
 * Write exactly `len` bytes from buf to fd.
 * Returns 0 on success, -1 on error.
 */
static int write_exact(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len)
    {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && errno == EAGAIN)
            {
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                int pr = poll(&pfd, 1, 30000); /* 30s timeout */
                if (pr <= 0)
                    return -1; /* timeout or error */
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/*
 * Read one framed CTAP2 request.
 *
 * @param fd         Client socket
 * @param cmd        Output: CTAP2 command byte
 * @param payload    Output buffer for CBOR payload
 * @param payload_len In: capacity; Out: actual payload length
 * @return 0 on success, -1 on error/EOF
 */
static int read_frame(int fd, uint8_t *cmd,
                      uint8_t *payload, size_t *payload_len)
{
    /* Header: 1 byte cmd + 2 bytes length (big-endian) */
    uint8_t hdr[3];
    if (read_exact(fd, hdr, 3) != 0)
        return -1;

    *cmd = hdr[0];
    uint16_t plen = ((uint16_t)hdr[1] << 8) | hdr[2];

    if (plen > *payload_len)
    {
        BIO_WARN("FIDO2 transport: payload too large (%u > %zu)",
                 plen, *payload_len);
        return -1;
    }

    if (plen > 0)
    {
        if (read_exact(fd, payload, plen) != 0)
            return -1;
    }

    *payload_len = plen;
    return 0;
}

/*
 * Write one framed CTAP2 response.
 *
 * @param fd         Client socket
 * @param status     CTAP2 status byte
 * @param payload    CBOR response payload (may be NULL if payload_len == 0)
 * @param payload_len Length of payload
 * @return 0 on success, -1 on error
 */
static int write_frame(int fd, uint8_t status,
                       const uint8_t *payload, size_t payload_len)
{
    uint8_t hdr[3];
    hdr[0] = status;
    hdr[1] = (payload_len >> 8) & 0xFF;
    hdr[2] = payload_len & 0xFF;

    if (write_exact(fd, hdr, 3) != 0)
        return -1;

    if (payload_len > 0 && payload)
    {
        if (write_exact(fd, payload, payload_len) != 0)
            return -1;
    }

    return 0;
}

static bool uid_in_group(uid_t uid, gid_t gid)
{
    struct passwd pwd;
    struct passwd *pw = NULL;
    char buf[1024];
    int ngroups = 0;
    gid_t *groups = NULL;
    bool found = false;

    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &pw) != 0 || !pw)
        return false;

    if (getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups) < 0 && ngroups > 0)
    {
        groups = (gid_t *)calloc((size_t)ngroups, sizeof(gid_t));
        if (!groups)
            return false;
        if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) >= 0)
        {
            for (int i = 0; i < ngroups; i++)
            {
                if (groups[i] == gid)
                {
                    found = true;
                    break;
                }
            }
        }
        free(groups);
    }

    return found;
}

static bool peer_is_authorized(uid_t uid)
{
    if (uid == 0)
        return true;

    struct group *grp = getgrnam("bioauth");
    if (!grp)
        return false;

    return uid_in_group(uid, grp->gr_gid);
}

/* ── Internal: Client handler ────────────────────────────────── */

/*
 * Handle a single connected client.
 * Process requests in a loop until the client disconnects.
 *
 * Each request is: [cmd(1)] [len(2 BE)] [cbor(len)]
 * Each response is: [status(1)] [len(2 BE)] [cbor(len)]
 */
static void handle_client(bio_fido2_transport_t *tp, int client_fd)
{
    uint8_t req_buf[BIOAUTH_FIDO2_MAX_MSG];
    uint8_t rsp_buf[BIOAUTH_FIDO2_MAX_MSG];
    int request_count = 0;

    /* Get peer credentials for logging */
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    pid_t peer_pid = 0;
    uid_t peer_uid = 0;
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                   &cred, &cred_len) == 0)
    {
        peer_pid = cred.pid;
        peer_uid = cred.uid;
    }
    BIO_INFO("FIDO2 transport: client connected (pid=%d, uid=%d)",
             (int)peer_pid, (int)peer_uid);

    /* Set a receive timeout to avoid blocking forever */
    struct timeval tv;
    tv.tv_sec = BIO_FIDO2_CLIENT_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    while (tp->running)
    {
        if (++request_count > BIO_FIDO2_MAX_REQUESTS_PER_CLIENT)
        {
            BIO_WARN("FIDO2 transport: closing client after %d requests",
                     BIO_FIDO2_MAX_REQUESTS_PER_CLIENT);
            break;
        }

        uint8_t cmd = 0;
        size_t req_len = sizeof(req_buf);

        if (read_frame(client_fd, &cmd, req_buf, &req_len) != 0)
        {
            /* Client disconnected or error */
            break;
        }

        BIO_DEBUG("FIDO2 transport: cmd=0x%02X, payload=%zu bytes",
                  cmd, req_len);

        /* Process the CTAP2 command */
        size_t rsp_len = sizeof(rsp_buf);
        uint8_t status = bio_fido2_process(tp->fido2_ctx, cmd,
                                           req_buf, req_len,
                                           rsp_buf, &rsp_len);

        /* For commands that don't produce output (e.g., Reset),
         * rsp_len is 0 but status is still sent */
        if (status != CTAP2_OK)
        {
            /* On error, no response payload */
            rsp_len = 0;
        }

        BIO_DEBUG("FIDO2 transport: status=0x%02X, response=%zu bytes",
                  status, rsp_len);

        if (write_frame(client_fd, status, rsp_buf, rsp_len) != 0)
        {
            BIO_WARN("FIDO2 transport: failed to send response");
            break;
        }
    }

    BIO_INFO("FIDO2 transport: client disconnected (pid=%d)", (int)peer_pid);
    close(client_fd);
}

/* ── Internal: Socket setup ──────────────────────────────────── */

/*
 * Create and bind a Unix domain socket.
 * Sets proper permissions (0660) and ownership.
 */
static int create_listen_socket(const char *path)
{
    /* Remove stale socket file */
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        BIO_ERROR("FIDO2 transport: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    /* Set umask for socket file permissions (srw-rw----) */
    mode_t old_umask = umask(0117);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        BIO_ERROR("FIDO2 transport: bind(%s) failed: %s", path, strerror(errno));
        umask(old_umask);
        close(fd);
        return -1;
    }

    umask(old_umask);

    /* Try to set group to "bioauth" if it exists, for access control */
    struct group *grp = getgrnam("bioauth");
    if (grp)
    {
        if (chown(path, 0, grp->gr_gid) != 0)
        {
            BIO_WARN("FIDO2 transport: chown(%s, 0, %d) failed: %s",
                     path, (int)grp->gr_gid, strerror(errno));
        }
    }

    if (listen(fd, 8) < 0)
    {
        BIO_ERROR("FIDO2 transport: listen() failed: %s", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}

/* ── Internal: Self-pipe for clean shutdown ──────────────────── */

static int g_shutdown_pipe[2] = {-1, -1};

/* ── Public API ──────────────────────────────────────────────── */

int bio_fido2_transport_init(bio_fido2_transport_t *tp,
                             bio_fido2_ctx_t *fido2_ctx,
                             const char *sock_path)
{
    if (!tp || !fido2_ctx)
        return BIO_ERR_INVALID_PARAM;

    memset(tp, 0, sizeof(*tp));
    tp->fido2_ctx = fido2_ctx;
    tp->listen_fd = -1;
    tp->max_clients = 8;

    if (sock_path)
    {
        strncpy(tp->sock_path, sock_path, sizeof(tp->sock_path) - 1);
    }
    else
    {
        strncpy(tp->sock_path, BIOAUTH_FIDO2_SOCK_PATH,
                sizeof(tp->sock_path) - 1);
    }

    /* Ensure directory exists */
    char dir[256];
    strncpy(dir, tp->sock_path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *last_slash = strrchr(dir, '/');
    if (last_slash)
    {
        *last_slash = '\0';
        mkdir(dir, 0755);
    }

    BIO_INFO("FIDO2 transport: initialized (socket=%s)", tp->sock_path);
    return BIO_OK;
}

int bio_fido2_transport_run(bio_fido2_transport_t *tp)
{
    if (!tp)
        return BIO_ERR_INVALID_PARAM;

    /* Create self-pipe for shutdown signaling.
     * The caller is responsible for signal handling and should call
     * bio_fido2_transport_stop() which writes to this pipe to wake
     * the select() loop.  We do NOT install signal handlers here
     * to avoid overriding the caller's handlers (e.g., fido2_main.c). */
    if (pipe(g_shutdown_pipe) < 0)
    {
        BIO_ERROR("FIDO2 transport: pipe() failed: %s", strerror(errno));
        return BIO_ERR_IO;
    }
    fcntl(g_shutdown_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_shutdown_pipe[1], F_SETFL, O_NONBLOCK);
    fcntl(g_shutdown_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(g_shutdown_pipe[1], F_SETFD, FD_CLOEXEC);

    /* Create listening socket */
    tp->listen_fd = create_listen_socket(tp->sock_path);
    if (tp->listen_fd < 0)
    {
        close(g_shutdown_pipe[0]);
        close(g_shutdown_pipe[1]);
        g_shutdown_pipe[0] = g_shutdown_pipe[1] = -1;
        return BIO_ERR_IO;
    }

    tp->running = true;
    BIO_INFO("FIDO2 transport: listening on %s", tp->sock_path);

    /* Main accept loop using select() */
    while (tp->running)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tp->listen_fd, &rfds);
        FD_SET(g_shutdown_pipe[0], &rfds);

        int maxfd = tp->listen_fd;
        if (g_shutdown_pipe[0] > maxfd)
            maxfd = g_shutdown_pipe[0];

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = select(maxfd + 1, &rfds, NULL, NULL, &timeout);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            BIO_ERROR("FIDO2 transport: select() failed: %s", strerror(errno));
            break;
        }

        if (ready == 0)
        {
            /* Timeout — check running flag */
            continue;
        }

        /* Check shutdown pipe */
        if (FD_ISSET(g_shutdown_pipe[0], &rfds))
        {
            BIO_INFO("FIDO2 transport: shutdown signal received");
            break;
        }

        /* Accept new connection */
        if (FD_ISSET(tp->listen_fd, &rfds))
        {
            struct sockaddr_un client_addr;
            socklen_t client_len = sizeof(client_addr);

            int client_fd = accept(tp->listen_fd,
                                   (struct sockaddr *)&client_addr,
                                   &client_len);
            if (client_fd < 0)
            {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                BIO_WARN("FIDO2 transport: accept() failed: %s",
                         strerror(errno));
                continue;
            }

            /* Verify peer credentials for security */
            struct ucred ucred;
            socklen_t ucred_len = sizeof(ucred);
            if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                           &ucred, &ucred_len) != 0)
            {
                BIO_WARN("FIDO2 transport: cannot get peer credentials");
                close(client_fd);
                continue;
            }

            /* Optional: restrict access to specific UIDs/groups here.
             * For now, we allow all local users (socket permissions
             * already restrict via filesystem). */
            BIO_DEBUG("FIDO2 transport: accepted connection from "
                      "pid=%d uid=%d gid=%d",
                      ucred.pid, ucred.uid, ucred.gid);

            if (!peer_is_authorized((uid_t)ucred.uid))
            {
                BIO_WARN("FIDO2 transport: rejecting unauthorized uid=%d",
                         (int)ucred.uid);
                close(client_fd);
                continue;
            }

            /*
             * Handle client synchronously (single-threaded).
             * For a production authenticator, consider fork() or
             * a thread pool. We use single-threaded to avoid
             * concurrency issues with the credential store.
             */
            handle_client(tp, client_fd);
        }
    }

    tp->running = false;

    /* Cleanup */
    close(g_shutdown_pipe[0]);
    close(g_shutdown_pipe[1]);
    g_shutdown_pipe[0] = g_shutdown_pipe[1] = -1;

    BIO_INFO("FIDO2 transport: event loop exited");
    return BIO_OK;
}

void bio_fido2_transport_stop(bio_fido2_transport_t *tp)
{
    if (!tp)
        return;
    tp->running = false;

    /* Signal via pipe to wake up select() */
    if (g_shutdown_pipe[1] >= 0)
    {
        uint8_t b = 1;
        ssize_t n = write(g_shutdown_pipe[1], &b, 1);
        (void)n;
    }
}

void bio_fido2_transport_cleanup(bio_fido2_transport_t *tp)
{
    if (!tp)
        return;

    if (tp->listen_fd >= 0)
    {
        close(tp->listen_fd);
        tp->listen_fd = -1;
    }

    /* Remove socket file */
    if (tp->sock_path[0])
    {
        unlink(tp->sock_path);
    }

    BIO_INFO("FIDO2 transport: cleaned up");
}
