
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <AP_HAL/AP_HAL.h>

#if HAL_OS_SOCKETS

#include "Socket.h"

/*
  constructor
 */
SocketAPM::SocketAPM(bool _datagram) :
    SocketAPM(_datagram, 
              socket(AF_INET, _datagram?SOCK_DGRAM:SOCK_STREAM, 0))
{}

SocketAPM::SocketAPM(bool _datagram, int _fd) :
    datagram(_datagram),
    fd(_fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (!datagram) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
}

SocketAPM::~SocketAPM()
{
    if (fd != -1) {
        ::close(fd);
        fd = -1;
    }
}

void SocketAPM::make_sockaddr(const char *address, uint16_t port, struct sockaddr_in &sockaddr)
{
    memset(&sockaddr, 0, sizeof(sockaddr));

#ifdef HAVE_SOCK_SIN_LEN
    sockaddr.sin_len = sizeof(sockaddr);
#endif
    sockaddr.sin_port = htons(port);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(address);
}

/*
  connect the socket
 */
bool SocketAPM::connect(const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    if (::connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        return false;
    }
    return true;
}

/*
  bind the socket
 */
bool SocketAPM::bind(const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    if (::bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        return false;
    }
    return true;
}

/*
  set SO_REUSEADDR
 */
bool SocketAPM::reuseaddress(void) const
{
    int one = 1;
    return (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != -1);
}

/*
  set blocking state
 */
bool SocketAPM::set_blocking(bool blocking) const
{
    int fcntl_ret;
    if (blocking) {
        fcntl_ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    } else {
        fcntl_ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    }
    return fcntl_ret != -1;
}

/*
  set cloexec state
 */
bool SocketAPM::set_cloexec() const
{
    return (fcntl(fd, F_SETFD, FD_CLOEXEC) != -1);
}

/*
  send some data
 */
ssize_t SocketAPM::send(const void *buf, size_t size) const
{
    return ::send(fd, buf, size, 0);
}

/*
  send some data
 */
ssize_t SocketAPM::sendto(const void *buf, size_t size, const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);
    return ::sendto(fd, buf, size, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
}

/*
  receive some data
 */
ssize_t SocketAPM::recv(void *buf, size_t size, uint32_t timeout_ms)
{
    if (!pollin(timeout_ms)) {
        return -1;
    }
    socklen_t len = sizeof(in_addr);
    return ::recvfrom(fd, buf, size, MSG_DONTWAIT, (sockaddr *)&in_addr, &len);
}

/*
  return the IP address and port of the last received packet
 */
void SocketAPM::last_recv_address(const char *&ip_addr, uint16_t &port) const
{
    ip_addr = inet_ntoa(in_addr.sin_addr);
    port = ntohs(in_addr.sin_port);
}

void SocketAPM::set_broadcast(void) const
{
    int one = 1;
    setsockopt(fd,SOL_SOCKET,SO_BROADCAST,(char *)&one,sizeof(one));
}

/*
  SSL socket constructor
 */
SSLSocketAPM::SSLSocketAPM(bool _datagram) :
    SocketAPM(_datagram),
    ssl_ctx(nullptr),
    ssl(nullptr)
{}

SSLSocketAPM::SSLSocketAPM(bool _datagram, int _fd, WOLFSSL_CTX *_ssl_ctx) :
    SocketAPM(_datagram, _fd),
    ssl_ctx(_ssl_ctx),
    ssl(nullptr)
{}

SSLSocketAPM::~SSLSocketAPM()
{
    if (ssl != nullptr) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = nullptr;
    }
}

/*
  SSL connect
 */
bool SSLSocketAPM::connect(const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    if (SocketAPM::connect(address, port)) {
        ssl = wolfSSL_new(ssl_ctx);
        wolfSSL_set_fd(ssl, fd);

        if (wolfSSL_connect(ssl) == SSL_SUCCESS) {
            return true;
        }
    }
    return false;
}

/*
  SSL send
 */
ssize_t SSLSocketAPM::send(const void *buf, size_t size) const
{
    return wolfSSL_write(ssl, buf, size);
}

/*
  SSL sendto
 */
ssize_t SSLSocketAPM::sendto(const void *buf, size_t size, const char *address, uint16_t port)
{
    // Not supported for SSL sockets
    return -1;
}

/*
  SSL receive
 */
ssize_t SSLSocketAPM::recv(void *buf, size_t size) const
{
    return wolfSSL_read(ssl, buf, size);
}

/*
  SSL receivefrom
 */
ssize_t SSLSocketAPM::recvfrom(void *buf, size_t size, char *address, uint16_t &port)
{
    // Not supported for SSL sockets
    return -1;
}

#endif // HAL_OS_SOCKETS
