#pragma once

#include <winsock2.h>

#define SECURITY_WIN32
#include <security.h>

#include <string>
#include <string_view>

// Presence link connection: plain TCP, or TLS 1.2 via SChannel.
class Connection {
public:
    Connection() = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    ~Connection() { close(); }

    // Take ownership of a connected blocking socket.
    void attach(SOCKET s);

    // TLS handshake on the attached socket. verify: check the certificate
    // against the system trust store and host. pin_sha256: hex SHA-256 of the
    // server certificate; when set it replaces the system check (self-signed).
    bool start_tls(const std::string& host, bool verify, const std::string& pin_sha256);

    bool is_open() const { return sock_ != INVALID_SOCKET; }
    SOCKET socket() const { return sock_; }

    bool write(std::string_view data);

    // Read once from the socket and append any plaintext to out. false when the
    // connection closed or failed.
    bool read(std::string& out);

    void close();

private:
    bool handshake(const std::wstring& host, std::string initial);
    bool send_raw(const char* data, size_t len);
    bool check_pin(const std::string& pin);

    SOCKET sock_ = INVALID_SOCKET;
    bool tls_ = false;
    CredHandle cred_{};
    CtxtHandle ctx_{};
    bool have_cred_ = false;
    bool have_ctx_ = false;
    SecPkgContext_StreamSizes sizes_{};
    std::string cipher_; // received ciphertext not yet decrypted
};
