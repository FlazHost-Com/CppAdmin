#pragma once
#include <drogon/HttpFilter.h>
#include <string>

// Generates a CSRF token (stored in session), validates it on mutating requests.
// Token is read from (in priority order): body field _csrf → query param _csrf → header X-CSRF-Token.
// This order matches NodeAdmin's body||query||header lookup and handles the DELETE caveat
// (Go/Drogon don't parse body for DELETE — token must be in query for form deletes).
// GET/HEAD requests pass through without validation.
class CsrfFilter : public drogon::HttpFilter<CsrfFilter> {
public:
    void doFilter(const drogon::HttpRequestPtr &req,
                  drogon::FilterCallback      &&fcb,
                  drogon::FilterChainCallback &&fccb) override;

    // Generate a new token (or return existing) and store in session.
    static std::string generateToken(const drogon::HttpRequestPtr &req);

    // Read token from request (body → query → header).
    static std::string extractToken(const drogon::HttpRequestPtr &req);

private:
    static std::string randomHex(size_t bytes);
};
