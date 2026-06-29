#include "AuthWebController.h"
#include "../../../include/helpers/ViewHelper.h"
#include "../../../include/helpers/FlashHelper.h"
#include <json/json.h>

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using drogon::HttpResponse;

// Load setting and inject logo/login_image into view data (best-effort — falls back to defaults).
static drogon::Task<void> injectSettingAssets(drogon::HttpViewData &data,
                                               std::shared_ptr<ISettingService> svc) {
    try {
        auto s = co_await svc->findFirst();
        data["settingLogo"]       = std::string(s.getLogo()       ? *s.getLogo()       : "");
        data["settingLoginImage"] = std::string(s.getLoginImage() ? *s.getLoginImage() : "");
        data["settingTheme"]      = s.getValueOfTheme();
    } catch (...) {
        data["settingLogo"]       = std::string("/be/default/vendor/fontawesome-free/svgs/solid/chart-line.svg");
        data["settingLoginImage"] = std::string("");
        data["settingTheme"]      = std::string("blue");
    }
}

// ── showLogin ─────────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::showLogin(HttpRequestPtr req) {
    drogon::HttpViewData data;
    co_await injectSettingAssets(data, settingSvc_);
    prepareViewData(data, req, data.get<std::string>("settingTheme"));
    co_return renderView("views::be::admin::auth::login", data);
}

// ── postLogin ─────────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::postLogin(HttpRequestPtr req) {
    std::string email    = req->getParameter("email");
    std::string password = req->getParameter("password");
    std::string loginErr;
    try {
        auto result = co_await auth_->login(email, password);
        std::string userId = result.user.getValueOfId();
        req->session()->insert("currentUser", userId);

        // Store user role names in session for hasRole() in templates
        try {
            auto roles = co_await userSvc_->rolesOf(userId);
            Json::Value arr(Json::arrayValue);
            for (const auto &r : roles) arr.append(r.getValueOfName());
            Json::FastWriter w;
            req->session()->insert("userRolesJson", w.write(arr));
        } catch (...) {
            req->session()->insert("userRolesJson", std::string{"[]"});
        }

        co_return HttpResponse::newRedirectionResponse("/admin/v1/dashboard");
    } catch (const std::exception &e) {
        loginErr = e.what();
    }
    // co_await not permitted inside catch — render error response outside the catch block
    drogon::HttpViewData data;
    co_await injectSettingAssets(data, settingSvc_);
    prepareViewData(data, req, data.get<std::string>("settingTheme"));
    Json::Value arr(Json::arrayValue);
    arr.append(loginErr);
    Json::FastWriter w;
    data["errorMessages"] = w.write(arr);
    co_return renderView("views::be::admin::auth::login", data);
}

// ── showRegister ──────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::showRegister(HttpRequestPtr req) {
    drogon::HttpViewData data;
    co_await injectSettingAssets(data, settingSvc_);
    prepareViewData(data, req, data.get<std::string>("settingTheme"));
    co_return renderView("views::be::admin::auth::signup", data);
}

// ── postRegister ──────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::postRegister(HttpRequestPtr req) {
    RegisterInput input;
    input.name     = req->getParameter("name");
    input.email    = req->getParameter("email");
    input.password = req->getParameter("password");
    input.phone    = req->getParameter("phone");

    auto user = co_await auth_->registerUser(std::move(input));
    req->session()->insert("currentUser", user.getValueOfId());
    co_return HttpResponse::newRedirectionResponse("/admin/v1/dashboard");
}

// ── postLogout ────────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::postLogout(HttpRequestPtr req) {
    req->session()->clear();
    co_return HttpResponse::newRedirectionResponse("/auth/login");
}

// ── showResetReq ──────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::showResetReq(HttpRequestPtr req) {
    drogon::HttpViewData data;
    co_await injectSettingAssets(data, settingSvc_);
    prepareViewData(data, req, data.get<std::string>("settingTheme"));
    co_return renderView("views::be::admin::auth::reset_req", data);
}

// ── postResetReq ──────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::postResetReq(HttpRequestPtr req) {
    ResetRequestInput input;
    input.email = req->getParameter("email");
    co_await auth_->requestPasswordReset(std::move(input));
    Flash::setSuccess(req, "OTP Send Success.");
    co_return HttpResponse::newRedirectionResponse("/admin/v1/auth/reset/proc");
}

// ── showResetProc ─────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::showResetProc(HttpRequestPtr req) {
    drogon::HttpViewData data;
    co_await injectSettingAssets(data, settingSvc_);
    prepareViewData(data, req, data.get<std::string>("settingTheme"));
    co_return renderView("views::be::admin::auth::reset_proc", data);
}

// ── postResetProc ─────────────────────────────────────────────────────────────
drogon::Task<HttpResponsePtr>
AuthWebController::postResetProc(HttpRequestPtr req) {
    ResetProcessInput input;
    input.email       = req->getParameter("email");
    input.otp         = req->getParameter("otp");
    input.newPassword = req->getParameter("new_password");
    co_await auth_->processPasswordReset(std::move(input));
    Flash::setSuccess(req, "Reset Password Success.");
    co_return HttpResponse::newRedirectionResponse("/auth/login");
}
