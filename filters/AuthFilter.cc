#include "AuthFilter.h"
#include "include/AppConfig.h"
#include "include/helpers/JwtHelper.h"
#include <drogon/HttpResponse.h>
#include <json/json.h>

void AuthFilter::doFilter(const drogon::HttpRequestPtr &req,
                           drogon::FilterCallback      &&fcb,
                           drogon::FilterChainCallback &&fccb) {
    const std::string &path = req->path();
    bool isApi = (path.rfind("/api/", 0) == 0);

    // ── API path: expect "Authorization: Bearer <token>" ──────────────────────
    if (isApi) {
        auto auth = req->getHeader("Authorization");
        std::string token;
        if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);

        if (!token.empty()) {
            auto result = jwt_helper::verify(token, AppConfig::instance().jwtSecret);
            if (result.valid) {
                req->attributes()->insert("currentUser",  result.sub);
                req->attributes()->insert("currentToken", token);
                fccb();
                return;
            }
        }
        auto body = std::make_shared<Json::Value>();
        (*body)["success"] = false;
        (*body)["message"] = "Unauthorized";
        auto r = drogon::HttpResponse::newHttpJsonResponse(*body);
        r->setStatusCode(drogon::k401Unauthorized);
        fcb(r);
        return;
    }

    // ── Web path: expect session ───────────────────────────────────────────────
    auto uid = req->session()->getOptional<std::string>("currentUser");
    if (uid && !uid->empty()) {
        req->attributes()->insert("currentUser", *uid);
        fccb();
        return;
    }

    // Not authenticated → redirect to login
    auto resp = drogon::HttpResponse::newRedirectionResponse("/auth/login");
    fcb(resp);
}
