#include "tls.hpp"

#include <windows.h>

#include <schannel.h>
#include <wincrypt.h>

#include <cctype>
#include <cstring>
#include <vector>

#include "logging.hpp"

namespace {

constexpr DWORD kRequest = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                           ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

std::wstring wide(const std::string& s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 1)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

std::string normalize_hex(const std::string& s)
{
    std::string out;
    for (char c : s)
        if (isxdigit(static_cast<unsigned char>(c)))
            out.push_back(static_cast<char>(tolower(static_cast<unsigned char>(c))));
    return out;
}

void set_timeout(SOCKET s, DWORD ms)
{
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}

} // namespace

void Connection::attach(SOCKET s)
{
    close();
    sock_ = s;
}

bool Connection::send_raw(const char* data, size_t len)
{
    while (len > 0)
    {
        int n = send(sock_, data, static_cast<int>(len), 0);
        if (n <= 0)
            return false;
        data += n;
        len -= n;
    }
    return true;
}

bool Connection::handshake(const std::wstring& host, std::string in)
{
    auto* target = const_cast<SEC_WCHAR*>(host.c_str());
    for (bool first = true;; first = false)
    {
        SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
        SecBuffer in_bufs[2] = {{static_cast<unsigned long>(in.size()), SECBUFFER_TOKEN, in.data()},
                                {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs};
        ULONG attrs = 0;

        SECURITY_STATUS st = InitializeSecurityContextW(
            &cred_, first ? nullptr : &ctx_, target, kRequest, 0, 0, first ? nullptr : &in_desc, 0,
            first ? &ctx_ : nullptr, &out_desc, &attrs, nullptr);
        if (first)
            have_ctx_ = true;

        if (st == SEC_E_INCOMPLETE_MESSAGE)
        {
            char buf[4096];
            int n = recv(sock_, buf, sizeof(buf), 0);
            if (n <= 0)
                return false;
            in.append(buf, n);
            continue;
        }

        if (out_buf.pvBuffer)
        {
            bool sent = out_buf.cbBuffer == 0 ||
                        send_raw(static_cast<const char*>(out_buf.pvBuffer), out_buf.cbBuffer);
            FreeContextBuffer(out_buf.pvBuffer);
            if (!sent)
                return false;
        }

        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED)
        {
            logging::info("TLS handshake failed: 0x%08lx", static_cast<unsigned long>(st));
            return false;
        }

        // Keep bytes the call did not consume (next handshake message or, once
        // done, the first application data).
        std::string extra;
        if (!first && in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0)
            extra = in.substr(in.size() - in_bufs[1].cbBuffer);
        in = std::move(extra);

        if (st == SEC_E_OK)
        {
            cipher_ = std::move(in);
            return true;
        }
        if (in.empty())
        {
            char buf[4096];
            int n = recv(sock_, buf, sizeof(buf), 0);
            if (n <= 0)
                return false;
            in.assign(buf, n);
        }
    }
}

bool Connection::check_pin(const std::string& pin)
{
    PCCERT_CONTEXT cert = nullptr;
    if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert) != SEC_E_OK || !cert)
        return false;
    BYTE hash[32];
    DWORD len = sizeof(hash);
    bool ok = CertGetCertificateContextProperty(cert, CERT_SHA256_HASH_PROP_ID, hash, &len) &&
              len == sizeof(hash);
    CertFreeCertificateContext(cert);
    if (!ok)
        return false;
    static const char* digits = "0123456789abcdef";
    std::string hex;
    for (BYTE b : hash)
    {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0xF]);
    }
    if (hex == normalize_hex(pin))
        return true;
    logging::info("TLS certificate pin mismatch (server sha256 %s)", hex.c_str());
    return false;
}

bool Connection::start_tls(const std::string& host, bool verify, const std::string& pin_sha256)
{
    bool pinned = !pin_sha256.empty();
    SCHANNEL_CRED cred{};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS |
                   (verify && !pinned ? SCH_CRED_AUTO_CRED_VALIDATION
                                      : SCH_CRED_MANUAL_CRED_VALIDATION);
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                  SECPKG_CRED_OUTBOUND, nullptr, &cred, nullptr, nullptr, &cred_,
                                  nullptr) != SEC_E_OK)
    {
        logging::info("TLS: AcquireCredentialsHandle failed");
        return false;
    }
    have_cred_ = true;

    set_timeout(sock_, 5000);
    bool ok = handshake(wide(host), {});
    set_timeout(sock_, 0);
    if (!ok)
        return false;
    if (pinned && !check_pin(pin_sha256))
        return false;
    if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes_) != SEC_E_OK)
        return false;
    tls_ = true;
    return true;
}

bool Connection::write(std::string_view data)
{
    if (sock_ == INVALID_SOCKET)
        return false;
    if (!tls_)
        return send_raw(data.data(), data.size());
    while (!data.empty())
    {
        size_t chunk = data.size() < sizes_.cbMaximumMessage ? data.size() : sizes_.cbMaximumMessage;
        std::vector<char> buf(sizes_.cbHeader + chunk + sizes_.cbTrailer);
        memcpy(buf.data() + sizes_.cbHeader, data.data(), chunk);
        SecBuffer bufs[4] = {
            {sizes_.cbHeader, SECBUFFER_STREAM_HEADER, buf.data()},
            {static_cast<unsigned long>(chunk), SECBUFFER_DATA, buf.data() + sizes_.cbHeader},
            {sizes_.cbTrailer, SECBUFFER_STREAM_TRAILER, buf.data() + sizes_.cbHeader + chunk},
            {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        if (EncryptMessage(&ctx_, 0, &desc, 0) != SEC_E_OK)
            return false;
        if (!send_raw(buf.data(), bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer))
            return false;
        data.remove_prefix(chunk);
    }
    return true;
}

bool Connection::read(std::string& out)
{
    if (sock_ == INVALID_SOCKET)
        return false;
    char buf[8192];
    int n = recv(sock_, buf, sizeof(buf), 0);
    if (n <= 0)
        return false;
    if (!tls_)
    {
        out.append(buf, n);
        return true;
    }
    cipher_.append(buf, n);
    while (!cipher_.empty())
    {
        SecBuffer bufs[4] = {{static_cast<unsigned long>(cipher_.size()), SECBUFFER_DATA, cipher_.data()},
                             {0, SECBUFFER_EMPTY, nullptr},
                             {0, SECBUFFER_EMPTY, nullptr},
                             {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS st = DecryptMessage(&ctx_, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE)
            return true; // wait for the rest of the record
        if (st == SEC_I_CONTEXT_EXPIRED)
            return false; // close_notify
        if (st != SEC_E_OK)
        {
            logging::info("TLS decrypt failed: 0x%08lx", static_cast<unsigned long>(st));
            return false;
        }
        std::string extra;
        for (auto& b : bufs)
        {
            if (b.BufferType == SECBUFFER_DATA && b.cbBuffer)
                out.append(static_cast<const char*>(b.pvBuffer), b.cbBuffer);
            else if (b.BufferType == SECBUFFER_EXTRA && b.cbBuffer)
                extra.assign(static_cast<const char*>(b.pvBuffer), b.cbBuffer);
        }
        cipher_ = std::move(extra);
    }
    return true;
}

void Connection::close()
{
    if (have_ctx_)
        DeleteSecurityContext(&ctx_);
    if (have_cred_)
        FreeCredentialsHandle(&cred_);
    have_ctx_ = have_cred_ = tls_ = false;
    cipher_.clear();
    if (sock_ != INVALID_SOCKET)
        closesocket(sock_);
    sock_ = INVALID_SOCKET;
}
