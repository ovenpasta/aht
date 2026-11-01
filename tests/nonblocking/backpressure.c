/* Copyright (C) 2026 Zack Boll
 * SPDX-License-Identifier: Apache-2.0
 * Test-only resource pressure: fill the real TCP send buffer while the peer
 * deliberately does not read. No TLS/backend state or functions are replaced.
 * The junk ciphertext is never processed by the peer; this test measures local
 * cleanup only, not protocol correctness. Linux qualification only. */
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int peer_socket(int port)
{
    for (int candidate = 0; candidate < FD_SETSIZE; ++candidate) {
        struct sockaddr_in peer;
        socklen_t size = sizeof peer;
        if (getpeername(candidate, (struct sockaddr *)&peer, &size) == 0 &&
            peer.sin_family == AF_INET && ntohs(peer.sin_port) == port) {
            return candidate;
        }
    }
    return -1;
}

/* Observe the queued-input premise without consuming TLS ciphertext. */
int task108_available(int port)
{
    int fd = peer_socket(port), available;
    if (fd < 0 || ioctl(fd, FIONREAD, &available) != 0)
        return -1;
    return available;
}

int task108_backpressure(int port)
{
    int fd = peer_socket(port);
    if (fd < 0)
        return -1;
    int size = 4096;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size) != 0)
        return -2;
    char bytes[65536];
    memset(bytes, 0, sizeof bytes);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t sent = send(fd, bytes, sizeof bytes, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            return -3;
        fd_set writes;
        FD_ZERO(&writes);
        FD_SET(fd, &writes);
        struct timeval wait = {.tv_sec = 0, .tv_usec = 200000};
        int ready = select(fd + 1, NULL, &writes, NULL, &wait);
        if (ready == 0)
            return 0;
        if (ready < 0)
            return -4;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 3)
            return -5;
    }
}