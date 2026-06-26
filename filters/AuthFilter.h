#pragma once
#include <drogon/HttpFilter.h>

// Checks that the user is authenticated via session (web) or JWT Bearer (API).
// Web (path != /api/): no session → redirect to /auth/login (302), NOT 401.
// API (/api/):          no/invalid token → 401 JSON.
// On success, injects "currentUser" (user id string) into request attributes.
class AuthFilter : public drogon::HttpFilter<AuthFilter> {
public:
    void doFilter(const drogon::HttpRequestPtr &req,
                  drogon::FilterCallback      &&fcb,
                  drogon::FilterChainCallback &&fccb) override;
};
