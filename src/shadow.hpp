#pragma once

#include "io.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <cstdlib>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <utility>

static inline const sockaddr_in CreateEndpointV4(const char *host,
                                                 const uint16_t port) noexcept {
  in_addr netHost{};
  if (inet_pton(AF_INET, host, &netHost) != 1) {
    ERR("Can't parse '%s' as a valid IPv4 address", host);
    exit(EXIT_FAILURE);
  }
  const sockaddr_in addr = {AF_INET, htons(port), {netHost}, {0}};
  return addr;
}

static inline const sockaddr_in6
CreateEndpointV6(const char *host, const uint16_t port) noexcept {
  in6_addr netHost{};
  if (inet_pton(AF_INET6, host, &netHost) != 1) {
    ERR("Can't parse '%s' as a valid IPv6 address", host);
    exit(EXIT_FAILURE);
  }
  const sockaddr_in6 addr = {AF_INET6, htons(port), 0, {netHost}, 0};
  return addr;
}

static inline void PrintEndpointV4(const char *msg, const sockaddr_in &addr) {
  char prettyAddr[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr.sin_addr, prettyAddr, sizeof(prettyAddr)) ==
      nullptr) {
    ERR_ERRNO("inet_ntop() failed for v4");
    return;
  }
  INF("%s'%s':'%u'", msg, prettyAddr, ntohs(addr.sin_port));
}

static inline void PrintEndpointV6(const char *msg, const sockaddr_in6 &addr) {
  char prettyAddr[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &addr.sin6_addr, prettyAddr, sizeof(prettyAddr)) ==
      nullptr) {
    ERR_ERRNO("inet_ntop() failed for v6");
  }
  INF("%s'%s':'%u'", msg, prettyAddr, ntohs(addr.sin6_port));
}

struct TSecurityOpts {
  const char *ca;
  const char *crt;
  const char *key;
};

class TSockProxy {
private:
  int fd;
  TSockProxy(const int sock) : fd(sock) {}
  TSockProxy(const TSockProxy &) = delete;
  TSockProxy &operator=(const TSockProxy &) = delete;

  void Destroy() noexcept {
    if (fd <= 0)
      return;
    INF("Shutdown and close sock %d", fd);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    fd = -1;
  }

public:
  TSockProxy(TSockProxy &&rhs) : fd(rhs.fd) { rhs.fd = -1; }

  ~TSockProxy() { Destroy(); }

  TSockProxy &operator=(TSockProxy &&rhs) {
    Destroy();
    fd = rhs.fd;
    rhs.fd = -1;
    return *this;
  }

  operator bool() const noexcept { return fd > 0; }

  static TSockProxy Empty() noexcept { return TSockProxy(-1); }

  inline void ForceStopCommunication() const noexcept {
    INF("Shutdown sock %d", fd);
    shutdown(fd, SHUT_RDWR);
  }

  inline int NativeHandle() const noexcept { return fd; }

  size_t TranferTo(TSockProxy &rhs) noexcept {
    return TIO::Tranfer(rhs.fd, fd);
  }

  bool WriteAll(const char *buf, size_t len) noexcept {
    return TIO::WriteAll(fd, buf, len);
  }

  size_t ReadSome(char *buf, size_t len) noexcept {
    return TIO::ReadSome(fd, buf, len);
  }

  size_t ReadAll(char *buf, size_t len) noexcept {
    return TIO::ReadAll(fd, buf, len);
  }

  friend class TSocketBase;
  friend class TSecuredSockProxy;
};

class TSecuredSockProxy : public TSockProxy {
private:
  SSL *sec;
  TSecuredSockProxy(int sock, SSL *sec_sock) : TSockProxy(sock), sec(sec_sock) {
    if (sec_sock == nullptr)
      return;
    SSL_set_fd(sec, fd);
  }
  TSecuredSockProxy(const TSecuredSockProxy &) = delete;
  TSecuredSockProxy &operator=(const TSecuredSockProxy &) = delete;

  void Destroy() noexcept {
    if (sec == nullptr)
      return;
    INF("Shutdown and free SSL* %p", sec);
    SSL_shutdown(sec);
    SSL_free(sec);
    sec = nullptr;
  }

  inline static TSecuredSockProxy Empty() noexcept {
    return TSecuredSockProxy(-1, nullptr);
  }

public:
  inline void ForceStopCommunication() const noexcept {
    INF("Shudown SSL* %p", sec);
    SSL_shutdown(sec);
    TSockProxy::ForceStopCommunication();
  }

  TSecuredSockProxy(TSecuredSockProxy &&rhs)
      : TSockProxy(std::move(rhs)), sec(rhs.sec) {
    rhs.sec = nullptr;
  }
  ~TSecuredSockProxy() { Destroy(); }
  TSecuredSockProxy &operator=(TSecuredSockProxy &&rhs) {
    Destroy();
    TSockProxy::operator=(std::move(rhs));
    sec = rhs.sec;
    rhs.sec = nullptr;
    return *this;
  }
  friend class TSecuredSocketBase;
};

class TSocketBase {
protected:
  int Socket_;

  TSocketBase(int domain) {
    Socket_ = socket(domain, SOCK_STREAM, 0);
    if (Socket_ < 0) {
      ERR_ERRNO("socket($domain, SOCK_STREAM, 0) failed");
      exit(EXIT_FAILURE);
    }
  }

  template <bool WithRetry = true>
  inline TSockProxy ClientConnect(const sockaddr *addr,
                                  const socklen_t addr_len) {
    while (true) {
      if (connect(Socket_, addr, addr_len) == 0)
        return TSockProxy(Socket_);
      /* error handling */
      if constexpr (WithRetry) {
        ERR_ERRNO("Wait TCP server starts for 1s");
        sleep(1);
        continue;
      } else {
        ERR_ERRNO("Can't connect to TCP server");
        return TSockProxy::Empty();
      }
    }
  }

  inline void
  BootstrapServerSocketBase(const sockaddr *addr, const socklen_t addr_len,
                            const int maxConnections = 1) const noexcept {
    if (bind(Socket_, addr, addr_len) < 0) {
      ERR_ERRNO("Bind() failed %d", Socket_);
      exit(EXIT_FAILURE);
    }

    if (listen(Socket_, maxConnections) < 0) {
      ERR_ERRNO("Listen() failed %d", Socket_);
      exit(EXIT_FAILURE);
    }
  }

  inline void
  BootstrapServerSocket(const sockaddr *addr, const socklen_t addr_len,
                        const int maxConnections = 1) const noexcept {
    /* Reuse the address; good for quick restarts */
    int optval = 1;
    if (setsockopt(Socket_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
        0) {
      ERR_ERRNO("setsockopt(SO_REUSEADDR) failed %d", Socket_);
      exit(EXIT_FAILURE);
    }

    BootstrapServerSocketBase(addr, addr_len, maxConnections);
  }

  inline TSockProxy ServerAccept(sockaddr *addr,
                                 socklen_t addr_len) const noexcept {
    /* Wait for TCP connection from client */
    int clientId = accept(Socket_, addr, &addr_len);
    if (clientId < 0) {
      ERR_ERRNO("Accept() failed %d", Socket_);
      return TSockProxy::Empty();
    }
    return TSockProxy(clientId);
  }

  /* Client socket is closed by TSockProxy and TSecuredSockProxy */
  inline void ServerShutdown() const noexcept {
    shutdown(Socket_, SHUT_RDWR);
    close(Socket_);
  }
};

class TClientSocketV4 : protected TSocketBase {
public:
  TClientSocketV4() : TSocketBase(AF_INET) {}

  inline TSockProxy Connect(const sockaddr_in &addr) {
    return ClientConnect((struct sockaddr *)&addr, sizeof(addr));
  }
  inline TSockProxy ConnectNoRetry(const sockaddr_in &addr) {
    return ClientConnect<false>((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TClientSocketV6 : protected TSocketBase {
public:
  TClientSocketV6() : TSocketBase(AF_INET6) {}

  inline TSockProxy Connect(const sockaddr_in6 &addr) {
    return ClientConnect((struct sockaddr *)&addr, sizeof(addr));
  }
  inline TSockProxy ConnectNoRetry(const sockaddr_in6 &addr) {
    return ClientConnect<false>((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TServerSocketV4 : protected TSocketBase {
public:
  TServerSocketV4(const uint16_t listenPort, const int maxConnections = 1)
      : TSocketBase(AF_INET) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listenPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    BootstrapServerSocket((struct sockaddr *)&addr, sizeof(addr),
                          maxConnections);
  }

  ~TServerSocketV4() {
    INF("Close v4 server sock %d", Socket_);
    ServerShutdown();
  }

  inline TSockProxy Accept(sockaddr_in &addr) {
    return ServerAccept((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TServerSocketV6 : protected TSocketBase {
public:
  TServerSocketV6(const uint16_t listenPort, const int maxConnections = 1)
      : TSocketBase(AF_INET6) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(listenPort);
    addr.sin6_addr = IN6ADDR_ANY_INIT;

    BootstrapServerSocket((struct sockaddr *)&addr, sizeof(addr),
                          maxConnections);
  }

  ~TServerSocketV6() {
    INF("Close v6 server sock %d", Socket_);
    ServerShutdown();
  }

  inline TSockProxy Accept(sockaddr_in6 &addr) {
    return ServerAccept((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TSecuredSocketBase : public TSocketBase {
private:
  SSL_CTX *Context_;

public:
  TSecuredSocketBase(int domain, bool isServer, int verifyFlags,
                     const TSecurityOpts &sec) noexcept
      : TSocketBase(domain) {
    const SSL_METHOD *method;
    if (isServer)
      method = TLS_server_method();
    else
      method = TLS_client_method();

    Context_ = SSL_CTX_new(method);

    if (Context_ == nullptr) {
      ERR_ERRNO("SSL_CTX_new() failed");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(Context_, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_min_proto_version(Context_, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(Context_, TLS1_2_VERSION);

    SSL_CTX_set_verify(Context_, verifyFlags, NULL);
    SSL_CTX_set_verify_depth(Context_, 1);

    if (SSL_CTX_use_certificate_chain_file(Context_, sec.ca) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(Context_, sec.ca, NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(Context_, sec.crt, SSL_FILETYPE_PEM) <=
        0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(Context_, sec.key, SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(Context_)) {
      ERR("Private key does not match the public certificate");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
  }
  ~TSecuredSocketBase() {
    INF("Free SSL_CTX* %p\n", Context_);
    SSL_CTX_free(Context_);
  }

protected:
  inline TSecuredSockProxy
  SecuredClientConnectImpl(const sockaddr *addr, socklen_t addr_len) noexcept {
    if (connect(Socket_, addr, addr_len) != 0) {
      ERR_ERRNO("Can't connect to TCP server");
      return TSecuredSockProxy::Empty();
    }
    /* we are connected */
    TSecuredSockProxy sock(Socket_, SSL_new(Context_));
    if (SSL_connect(sock.sec) != 1) {
      ERR_print_errors_fp(stderr);
      ERR("mTLS handshake failed. "
          "Certificates are wrong, retry has no sense, exit");
      exit(EXIT_FAILURE);
    }
    if (BIO_get_ktls_send(SSL_get_wbio(sock.sec)) == 0 ||
        BIO_get_ktls_recv(SSL_get_rbio(sock.sec)) == 0) {
      ERR("KTLS initialization failed. "
          "Kernel tls module is not loaded - retry is meaningless, exit");
      exit(EXIT_FAILURE);
    }
    return sock;
  }

  template <bool WithRetry = true>
  inline TSecuredSockProxy SecuredClientConnect(const sockaddr *addr,
                                                socklen_t addr_len) noexcept {
    if constexpr (!WithRetry)
      return SecuredClientConnectImpl(addr, addr_len);
    else {
      while (true) {
        TSecuredSockProxy secSock = SecuredClientConnectImpl(addr, addr_len);
        if (secSock)
          return secSock;
        sleep(1);
        continue;
      }
    }
  }

  inline TSecuredSockProxy SecuredServerAccept(struct sockaddr *addr,
                                               socklen_t addr_len) {
    int clientId = accept(Socket_, addr, &addr_len);
    if (clientId < 0) {
      ERR_ERRNO("Secured Accept() failed %d", Socket_);
      return TSecuredSockProxy::Empty();
    }

    TSecuredSockProxy sock(clientId, SSL_new(Context_));
    if (SSL_accept(sock.sec) <= 0) {
      ERR_print_errors_fp(stderr);
      ERR("mTLS handshake failed: certificates are wrong");
      return TSecuredSockProxy::Empty();
    }
    if (BIO_get_ktls_send(SSL_get_wbio(sock.sec)) == 0 ||
        BIO_get_ktls_recv(SSL_get_rbio(sock.sec)) == 0) {
      ERR("KTLS initialization failed: check kernel tls module is loaded");
      return TSecuredSockProxy::Empty();
    }
    return sock;
  }
};

class TSecuredClientSocketV4 : public TSecuredSocketBase {
public:
  TSecuredClientSocketV4(const TSecurityOpts &secOpts)
      : TSecuredSocketBase(AF_INET, false, SSL_VERIFY_PEER, secOpts) {}

  TSecuredSockProxy Connect(const sockaddr_in &addr) noexcept {
    return SecuredClientConnect((struct sockaddr *)&addr, sizeof(addr));
  }
  TSecuredSockProxy ConnectNoRetry(const sockaddr_in &addr) noexcept {
    return SecuredClientConnect<false>((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TSecuredClientSocketV6 : public TSecuredSocketBase {
public:
  TSecuredClientSocketV6(const TSecurityOpts &secOpts)
      : TSecuredSocketBase(AF_INET6, false, SSL_VERIFY_PEER, secOpts) {}

  TSecuredSockProxy Connect(const sockaddr_in6 &addr) noexcept {
    return SecuredClientConnect((struct sockaddr *)&addr, sizeof(addr));
  }
  TSecuredSockProxy ConnectNoRetry(const sockaddr_in6 &addr) noexcept {
    return SecuredClientConnect<false>((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TSecuredServerSocketV4 : public TSecuredSocketBase {
public:
  TSecuredServerSocketV4(const TSecurityOpts &secOpts,
                         const uint16_t listenPort,
                         const int maxConnections = 1)
      : TSecuredSocketBase(AF_INET, true,
                           SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                               SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           secOpts) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listenPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    BootstrapServerSocket((struct sockaddr *)&addr, sizeof(addr),
                          maxConnections);
  }

  ~TSecuredServerSocketV4() {
    INF("Close v4 secured server sock %d", Socket_);
    ServerShutdown();
  }

  inline TSecuredSockProxy Accept(sockaddr_in &addr) {
    return SecuredServerAccept((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TSecuredServerSocketV6 : public TSecuredSocketBase {
public:
  TSecuredServerSocketV6(const TSecurityOpts &secOpts,
                         const uint16_t listenPort,
                         const int maxConnections = 1)
      : TSecuredSocketBase(AF_INET6, true,
                           SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                               SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           secOpts) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(listenPort);
    addr.sin6_addr = IN6ADDR_ANY_INIT;

    BootstrapServerSocket((struct sockaddr *)&addr, sizeof(addr),
                          maxConnections);
  }

  ~TSecuredServerSocketV6() {
    INF("Close v6 secured server sock %d", Socket_);
    ServerShutdown();
  }

  inline TSecuredSockProxy Accept(sockaddr_in6 &addr) {
    return SecuredServerAccept((struct sockaddr *)&addr, sizeof(addr));
  }
};

class TServerSocketUnix : protected TSocketBase {
public:
  TServerSocketUnix(const char *spath, const int maxConnections = 1)
      : TSocketBase(AF_UNIX) {
    INF("Unlink '%s'", spath);
    unlink(spath);

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    const char *end = stpncpy(addr.sun_path, spath, sizeof(addr.sun_path));
    socklen_t len = sizeof(addr.sun_family) + (end - &addr.sun_path[0]);

    INF("Creating unix sock '%s'", addr.sun_path);
    BootstrapServerSocketBase((struct sockaddr *)&addr, len, maxConnections);
  }

  ~TServerSocketUnix() {
    INF("Close unix sock %d", Socket_);
    ServerShutdown();
  }

  TSockProxy Accept(sockaddr_un &addr) const noexcept {
    return ServerAccept((struct sockaddr *)&addr, sizeof(addr));
  }

  inline void ForceStopCommunication() const noexcept {
    INF("Shutdown unix sock %d", Socket_);
    shutdown(Socket_, SHUT_RDWR);
  }
};

enum class ECommand : uint32_t {
  REGISTER = 0xDADADADA,
  CHANNEL = 0xADADADAD,
  PING = 0xCAFECAFE,
};

struct TRegisterMe {
  ECommand Hello = ECommand::REGISTER;
  uint32_t RobotId;
  TRegisterMe(const uint32_t rId) : RobotId(rId) {}
  TRegisterMe() {}
} __attribute__((packed));

struct TChannelRequest {
  ECommand Hello = ECommand::CHANNEL;
  uint32_t RobotId;
  uint32_t ChannelId;
  TChannelRequest(const uint32_t rId, const uint32_t cId)
      : RobotId(rId), ChannelId(cId) {}
  TChannelRequest() {}
} __attribute__((packed));

struct TPingRequest {
  ECommand Hello = ECommand::PING;
} __attribute__((packed));
