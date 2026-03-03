/*
 * lochs push - Push an image to a registry
 *
 * Usage:
 *   lochs push <image>[:<tag>] [--registry <url>]
 *
 * Tars the image and uploads via HTTP PUT to the registry endpoint.
 * Default registry: http://localhost:5000 (local development)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "bsdulator/lochs.h"

static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Minimal HTTP PUT client using raw sockets.
 * Uploads data from a file to the specified URL.
 */
static int http_put_file(const char *host, int port, const char *path,
                         const char *filepath) {
    /* Get file size */
    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stderr, "Error: cannot stat '%s'\n", filepath);
        return -1;
    }

    /* Connect to host */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Error: cannot resolve host '%s'\n", host);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    /* Send HTTP PUT request */
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "PUT %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, port, (long)st.st_size);

    if (write(fd, header, (size_t)hlen) != hlen) {
        fprintf(stderr, "Error: failed to send HTTP header\n");
        close(fd);
        return -1;
    }

    /* Stream file content */
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", filepath);
        close(fd);
        return -1;
    }

    char buf[8192];
    size_t n;
    long total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) {
            fprintf(stderr, "Error: write failed during upload\n");
            fclose(f);
            close(fd);
            return -1;
        }
        total += w;
    }
    fclose(f);

    /* Read response status */
    char resp[1024];
    ssize_t rn = read(fd, resp, sizeof(resp) - 1);
    close(fd);

    if (rn > 0) {
        resp[rn] = '\0';
        /* Check for 2xx status */
        if (strstr(resp, " 200 ") || strstr(resp, " 201 ") || strstr(resp, " 204 ")) {
            return 0;
        }
        fprintf(stderr, "Registry response: %.80s\n", resp);
        return -1;
    }

    return 0;
}

int lochs_cmd_push(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs push <image>[:<tag>] [--registry <url>]\n");
        return 1;
    }

    const char *image_spec = argv[1];
    const char *registry_host = "localhost";
    int registry_port = 5000;

    /* Parse --registry flag */
    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "--registry") == 0) {
            const char *url = argv[i + 1];
            /* Simple parse: host:port */
            char host_buf[256];
            safe_strcpy(host_buf, url, sizeof(host_buf));
            /* Strip http:// prefix */
            char *h = host_buf;
            if (strncmp(h, "http://", 7) == 0) h += 7;
            if (strncmp(h, "https://", 8) == 0) h += 8;
            char *colon = strchr(h, ':');
            if (colon) {
                *colon = '\0';
                registry_port = atoi(colon + 1);
            }
            registry_host = h;
            i++;
        }
    }

    /* Parse image:tag */
    char repo[128], tag[64];
    const char *colon = strchr(image_spec, ':');
    if (colon) {
        size_t rlen = (size_t)(colon - image_spec);
        if (rlen >= sizeof(repo)) rlen = sizeof(repo) - 1;
        memcpy(repo, image_spec, rlen);
        repo[rlen] = '\0';
        safe_strcpy(tag, colon + 1, sizeof(tag));
    } else {
        safe_strcpy(repo, image_spec, sizeof(repo));
        safe_strcpy(tag, "latest", sizeof(tag));
    }

    /* Find the image path */
    const char *image_path = lochs_image_get_path(image_spec);
    if (!image_path) {
        fprintf(stderr, "Error: image '%s' not found locally\n", image_spec);
        fprintf(stderr, "Run 'lochs images' to see available images.\n");
        return 1;
    }

    /* Create tarball */
    char tarpath[512];
    snprintf(tarpath, sizeof(tarpath), "/tmp/lochs_push_%s_%s.tar.gz", repo, tag);

    printf("Compressing image '%s:%s'...\n", repo, tag);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "tar -czf '%s' -C '%s' . 2>/dev/null", tarpath, image_path);
    int r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: failed to create tarball\n");
        return 1;
    }

    /* Upload to registry */
    printf("Pushing to %s:%d...\n", registry_host, registry_port);
    char url_path[512];
    snprintf(url_path, sizeof(url_path), "/v2/%s/blobs/%s", repo, tag);

    r = http_put_file(registry_host, registry_port, url_path, tarpath);

    /* Clean up temp file */
    unlink(tarpath);

    if (r == 0) {
        printf("Successfully pushed %s:%s to %s:%d\n",
            repo, tag, registry_host, registry_port);
    } else {
        fprintf(stderr, "Error: push failed. Is the registry running at %s:%d?\n",
            registry_host, registry_port);
        return 1;
    }

    return 0;
}
