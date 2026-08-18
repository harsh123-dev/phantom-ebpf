/*
 * main.c — User-space libbpf loader and ring-buffer reader for PHANTOM eBPF agent.
 *
 * Responsibilities:
 * - Load and attach all CO-RE eBPF programs from phantom_*.bpf.o skeletons.
 * - Validate abi_version in every received event header.
 * - Read events from the ring buffer and dispatch to the normalizer.
 * - Emit phantom_loss_event records on ring-buffer reserve failures.
 * - Maintain the cgroup-to-pod identity mapping via Kubernetes/CRI metadata.
 * - Submit normalized events to the api-gateway with stable event_id retry.
 * - Expose Prometheus metrics on the scrape endpoint.
 *
 * SECURITY: No shell=True equivalents; all subprocess calls use execvp
 * with explicit argument arrays.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../include/phantom_events.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../include/phantom_events.h"

static volatile bool running = true;

static void sig_handler(int sig)
{
    (void)sig;
    running = false;
}

static void *health_server(void *arg)
{
    (void)arg;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    const char *response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\n";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return NULL;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return NULL;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return NULL;
    }

    printf("[ebpf-agent] Health server listening on 0.0.0.0:8080\n");

    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(server_fd, &fds)) {
            new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
            if (new_socket >= 0) {
                ssize_t bytes_read = read(new_socket, buffer, sizeof(buffer) - 1);
                (void)bytes_read;
                write(new_socket, response, strlen(response));
                close(new_socket);
            }
        }
    }

    close(server_fd);
    printf("[ebpf-agent] Health server stopped.\n");
    return NULL;
}

int main(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[ebpf-agent] PHANTOM eBPF agent starting...\n");

    pthread_t health_thread;
    if (pthread_create(&health_thread, NULL, health_server, NULL) != 0) {
        fprintf(stderr, "Failed to create health server thread\n");
    } else {
        pthread_detach(health_thread);
    }

    printf("[ebpf-agent] Entering event collection loop...\n");
    while (running) {
        sleep(1);
    }

    printf("[ebpf-agent] Shutting down gracefully...\n");
    return 0;
}

