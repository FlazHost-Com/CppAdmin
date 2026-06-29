#include "CsrfFilter.h"
#include <drogon/HttpResponse.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <sstream>
#include <iomanip>
#include <vector>

std::string CsrfFilter::randomHex(size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), (int)bytes);
    std::ostringstream oss;
    for (auto b : buf) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

std::string CsrfFilter::generateToken(const drogon::HttpRequestPtr &req) {
    auto existing = req->session()->getOptional<std::string>("_csrf");
    if (existing) return *existing;
    std::string tok = randomHex(24);
    req->session()->insert("_csrf", tok);
    return tok;
}

std::string CsrfFilter::extractToken(const drogon::HttpRequestPtr &req) {
    // 1. body field (form-urlencoded / multipart) — getParameter reads body for POST
    auto body = req->getParameter("_csrf");
    if (!body.empty()) return body;
    // 2. query param — getQuery reads URL query string only
    auto query = req->getQuery();
    // parse ?_csrf=VALUE from raw query string
    std::string key = "_csrf=";
    auto pos = query.find(key);
    if (pos != std::string::npos) {
        auto val = query.substr(pos + key.size());
        auto end = val.find('&');
        if (end != std::string::npos) val = val.substr(0, end);
        if (!val.empty()) return val;
    }
    // 3. custom header (lowercase per standard)
    auto hdr = req->getHeader("x-csrf-token");
    if (!hdr.empty()) return hdr;
    return "";
}

void CsrfFilter::doFilter(const drogon::HttpRequestPtr &req,
                           drogon::FilterCallback      &&fcb,
                           drogon::FilterChainCallback &&fccb) {
    auto method = req->method();
    // Skip safe methods
    if (method == drogon::Get || method == drogon::Head || method == drogon::Options) {
        // Generate token so it's available in views
        generateToken(req);
        fccb();
        return;
    }
    // Skip API paths (JWT stateless)
    const std::string &path = req->path();
    if (path.rfind("/api/", 0) == 0) {
        fccb();
        return;
    }

    std::string sessionTok;
    auto opt = req->session()->getOptional<std::string>("_csrf");
    if (opt) sessionTok = *opt;

    std::string submitted = extractToken(req);

    // Timing-safe compare — prevent length-based timing leaks
    bool mismatch = sessionTok.empty() || submitted.empty()
        || sessionTok.size() != submitted.size()
        || CRYPTO_memcmp(sessionTok.data(), submitted.data(), sessionTok.size()) != 0;
    if (mismatch) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k403Forbidden);
        resp->setContentTypeCode(drogon::CT_TEXT_HTML);
        resp->setBody("<h1>403 Invalid CSRF Token</h1>");
        fcb(resp);
        return;
    }
    fccb();
}
