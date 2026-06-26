// All modules implemented in their own Routes.cc files.
// registerAuthRoutes()       → AuthRoutes.cc  (Phase 1)
// registerAccessRoutes()     → AccessRoutes.cc (Phase 2)
// registerDashboardRoutes()  → DashboardRoutes.cc (Phase 3)
// registerComponentsRoutes() → ComponentsRoutes.cc (Phase 3)
// registerSettingRoutes()    → SettingRoutes.cc (Phase 3)
// registerProfileRoutes()    → ProfileRoutes.cc (Phase 3)
// registerMediaRoutes()      → MediaRoutes.cc  (Phase 4)

// Home: simple redirect only — no dedicated module file needed.
void registerHomeRoutes() {
    // Handled inside DashboardRoutes.cc via "/" and "/admin" redirects.
}
