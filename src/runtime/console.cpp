#include "runtime/console.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

void close_console_pair(ConsolePair& pair) {
    if (pair.master_fd >= 0) {
        close(pair.master_fd);
        pair.master_fd = -1;
    }
    if (pair.slave_fd >= 0) {
        close(pair.slave_fd);
        pair.slave_fd = -1;
    }
}

bool allocate_console_pair(ConsolePair& pair, std::string& error_message) {
    ConsolePair tmp;
    tmp.master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tmp.master_fd == -1) {
        error_message = std::string("posix_openpt failed: ") + std::strerror(errno);
        return false;
    }
    if (grantpt(tmp.master_fd) != 0) {
        error_message = std::string("grantpt failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    if (unlockpt(tmp.master_fd) != 0) {
        error_message = std::string("unlockpt failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    char slave_name_buf[PATH_MAX];
    if (ptsname_r(tmp.master_fd, slave_name_buf, sizeof(slave_name_buf)) != 0) {
        error_message = std::string("ptsname_r failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    tmp.slave_name = slave_name_buf;
    tmp.slave_fd = open(slave_name_buf, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tmp.slave_fd == -1) {
        error_message = std::string("open slave pty failed: ") + std::strerror(errno);
        close_console_pair(tmp);
        return false;
    }
    pair = tmp;
    return true;
}

bool send_console_fd(const ConsolePair& pair, const std::string& socket_path, std::string& error_message) {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        error_message = std::string("socket creation failed: ") + std::strerror(errno);
        return false;
    }
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        error_message = "console socket path too long";
        close(sock);
        return false;
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error_message = std::string("connect to console socket failed: ") + std::strerror(errno);
        close(sock);
        return false;
    }

    std::string payload = pair.slave_name.empty() ? "console" : pair.slave_name;
    struct iovec iov {};
    iov.iov_base = const_cast<char*>(payload.c_str());
    iov.iov_len = payload.size();

    char control[CMSG_SPACE(sizeof(int))];
    std::memset(control, 0, sizeof(control));

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &pair.master_fd, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    ssize_t sent = sendmsg(sock, &msg, 0);
    int saved_errno = errno;
    close(sock);
    if (sent == -1) {
        error_message = std::string("sendmsg failed: ") + std::strerror(saved_errno);
        return false;
    }
    return true;
}
