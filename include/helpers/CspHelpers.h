#pragma once
#include <drogon/utils/OStringStream.h>
#include <drogon/HttpViewData.h>
#include "HtmlEscape.h"
#include <string>

inline std::string v(const drogon::HttpViewData &d, const std::string &key) {
    return d.get<std::string>(key);
}

inline void hout(drogon::OStringStream &s, const std::string &val) {
    s << h(val);
}

inline void flashAlerts(drogon::OStringStream &out, const drogon::HttpViewData &d) {
    auto success = v(d, "flashSuccess");
    auto error   = v(d, "flashError");
    if (!success.empty())
        out << "<div class=\"alert alert-success\">" << h(success) << "</div>\n";
    if (!error.empty())
        out << "<div class=\"alert alert-error\">" << h(error) << "</div>\n";
}

inline void csrfInput(drogon::OStringStream &out, const drogon::HttpViewData &d) {
    out << "<input type=\"hidden\" name=\"_csrf\" value=\"" << h(v(d, "csrfToken")) << "\">\n";
}

inline void navItem(drogon::OStringStream &out,
                    const std::string &href, const std::string &label,
                    const std::string &icon, const std::string &currentPath) {
    bool active = (currentPath.find(href) != std::string::npos);
    out << "<a href=\"" << href << "\" class=\"nav-item";
    if (active) out << " active";
    out << "\"><span class=\"icon\">" << icon << "</span> " << h(label) << "</a>\n";
}

inline void themeCssVars(drogon::OStringStream &out, const drogon::HttpViewData &d) {
    out << ":root {\n";
    out << "  --primary:   " << v(d, "themePrimary")   << ";\n";
    out << "  --secondary: " << v(d, "themeSecondary") << ";\n";
    out << "  --theme-light: " << v(d, "themeLight")   << ";\n";
    out << "  --theme-dark:  " << v(d, "themeDark")    << ";\n";
    out << "}\n";
}
