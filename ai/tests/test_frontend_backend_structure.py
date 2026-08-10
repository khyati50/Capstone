"""Frontend & Backend Structure Validation Test Suite.

Since Node.js is not installed on this machine, these tests verify
the structural integrity of all frontend and backend source files:
- All 7 React page components exist with required exports
- All 7 Express route modules exist with proper patterns
- Frontend API client configuration
- Tailwind CSS and Vite configuration
- Package.json dependency declarations
"""

import pytest
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ──────────────────────────────────────────────
# Frontend React Component Structure Tests
# ──────────────────────────────────────────────


class TestFrontendComponentStructure:
    """Verify all 7 React dashboard page components exist and are well-formed."""

    PAGES_DIR = BASE_DIR / "frontend" / "src" / "pages"

    REQUIRED_PAGES = [
        "Dashboard.jsx",
        "AlertCenter.jsx",
        "Timeline.jsx",
        "ShapExplainer.jsx",
        "RiskGauge.jsx",
        "MitreMatrix.jsx",
        "Simulation.jsx",
    ]

    def test_pages_directory_exists(self):
        """Frontend pages directory must exist."""
        assert self.PAGES_DIR.exists()

    @pytest.mark.parametrize("page_name", REQUIRED_PAGES)
    def test_page_component_exists(self, page_name):
        """Each required page component file must exist."""
        assert (self.PAGES_DIR / page_name).exists(), f"Missing page: {page_name}"

    @pytest.mark.parametrize("page_name", REQUIRED_PAGES)
    def test_page_has_default_export(self, page_name):
        """Each page component must have an export default statement."""
        content = (self.PAGES_DIR / page_name).read_text(encoding="utf-8")
        assert "export default" in content, f"{page_name} missing export default"

    @pytest.mark.parametrize("page_name", REQUIRED_PAGES)
    def test_page_has_jsx_return(self, page_name):
        """Each page component must have a return statement with JSX."""
        content = (self.PAGES_DIR / page_name).read_text(encoding="utf-8")
        assert "return" in content, f"{page_name} missing return statement"

    @pytest.mark.parametrize("page_name", REQUIRED_PAGES)
    def test_page_is_not_empty(self, page_name):
        """Each page component must have meaningful content (>500 bytes)."""
        size = (self.PAGES_DIR / page_name).stat().st_size
        assert size > 500, f"{page_name} is too small ({size} bytes)"

    def test_app_jsx_exists(self):
        """Main App.jsx must exist."""
        assert (BASE_DIR / "frontend" / "src" / "App.jsx").exists()

    def test_app_jsx_has_navigation(self):
        """App.jsx must define navigation for dashboard pages."""
        content = (BASE_DIR / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        # App uses tab-based navigation with activeTab state or React Router
        assert "activeTab" in content or "Route" in content

    def test_api_client_exists(self):
        """Frontend API client module must exist."""
        api_dir = BASE_DIR / "frontend" / "src" / "api"
        assert api_dir.exists()
        client_file = api_dir / "client.js"
        assert client_file.exists()

    def test_api_client_uses_axios_or_fetch(self):
        """API client must use axios or fetch for HTTP requests."""
        content = (BASE_DIR / "frontend" / "src" / "api" / "client.js").read_text(encoding="utf-8")
        assert "axios" in content.lower() or "fetch" in content.lower()

    def test_main_jsx_exists(self):
        """Entry point main.jsx must exist."""
        assert (BASE_DIR / "frontend" / "src" / "main.jsx").exists()

    def test_index_css_exists(self):
        """Global stylesheet index.css must exist."""
        assert (BASE_DIR / "frontend" / "src" / "index.css").exists()


# ──────────────────────────────────────────────
# Frontend Configuration Tests
# ──────────────────────────────────────────────


class TestFrontendConfiguration:
    """Verify frontend build tools and dependencies."""

    def test_package_json_exists(self):
        """Frontend package.json must exist."""
        assert (BASE_DIR / "frontend" / "package.json").exists()

    def test_package_json_has_react(self):
        """package.json must declare react as dependency."""
        import json

        pkg = json.loads((BASE_DIR / "frontend" / "package.json").read_text())
        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))
        assert "react" in all_deps

    def test_package_json_has_dev_script(self):
        """package.json must have a 'dev' script for local development."""
        import json

        pkg = json.loads((BASE_DIR / "frontend" / "package.json").read_text())
        assert "dev" in pkg.get("scripts", {})

    def test_vite_or_build_config_exists(self):
        """Vite config file must exist."""
        vite_config = BASE_DIR / "frontend" / "vite.config.js"
        vite_config_ts = BASE_DIR / "frontend" / "vite.config.ts"
        assert vite_config.exists() or vite_config_ts.exists()

    def test_tailwind_config_exists(self):
        """Tailwind CSS config file must exist."""
        tw = BASE_DIR / "frontend" / "tailwind.config.js"
        tw_ts = BASE_DIR / "frontend" / "tailwind.config.ts"
        assert tw.exists() or tw_ts.exists()


# ──────────────────────────────────────────────
# Backend Express Route Structure Tests
# ──────────────────────────────────────────────


class TestBackendRouteStructure:
    """Verify all 7 Express backend route modules exist and are well-formed."""

    ROUTES_DIR = BASE_DIR / "backend" / "routes"

    REQUIRED_ROUTES = [
        "auth.js",
        "events.js",
        "alerts.js",
        "timeline.js",
        "risk.js",
        "mitre.js",
        "simulate.js",
    ]

    def test_routes_directory_exists(self):
        """Backend routes directory must exist."""
        assert self.ROUTES_DIR.exists()

    @pytest.mark.parametrize("route_file", REQUIRED_ROUTES)
    def test_route_file_exists(self, route_file):
        """Each required route file must exist."""
        assert (self.ROUTES_DIR / route_file).exists(), f"Missing route: {route_file}"

    @pytest.mark.parametrize("route_file", REQUIRED_ROUTES)
    def test_route_exports_router(self, route_file):
        """Each route file must export a router (module.exports)."""
        content = (self.ROUTES_DIR / route_file).read_text(encoding="utf-8")
        assert "module.exports" in content, f"{route_file} missing module.exports"

    @pytest.mark.parametrize("route_file", REQUIRED_ROUTES)
    def test_route_uses_express_router(self, route_file):
        """Each route file must use express.Router()."""
        content = (self.ROUTES_DIR / route_file).read_text(encoding="utf-8")
        assert "express.Router()" in content or "Router()" in content, f"{route_file} missing express.Router()"

    def test_server_js_exists(self):
        """Backend server.js entry point must exist."""
        assert (BASE_DIR / "backend" / "server.js").exists()

    def test_server_mounts_all_api_routes(self):
        """server.js must mount all 7 API route handlers."""
        content = (BASE_DIR / "backend" / "server.js").read_text(encoding="utf-8")
        required_mounts = [
            "/api/auth",
            "/api/events",
            "/api/alerts",
            "/api/timeline",
            "/api/risk",
            "/api/mitre",
            "/api/simulate",
        ]
        for mount in required_mounts:
            assert mount in content, f"server.js missing route mount: {mount}"

    def test_server_has_health_endpoint(self):
        """server.js must have a /api/health endpoint."""
        content = (BASE_DIR / "backend" / "server.js").read_text(encoding="utf-8")
        assert "/api/health" in content


# ──────────────────────────────────────────────
# Backend Configuration Tests
# ──────────────────────────────────────────────


class TestBackendConfiguration:
    """Verify backend dependencies and configuration files."""

    def test_backend_package_json_exists(self):
        """Backend package.json must exist."""
        assert (BASE_DIR / "backend" / "package.json").exists()

    def test_db_config_exists(self):
        """Database configuration module must exist."""
        db = BASE_DIR / "backend" / "config" / "db.js"
        assert db.exists()

    def test_socket_service_exists(self):
        """Socket.IO service module must exist."""
        sock = BASE_DIR / "backend" / "services" / "socketService.js"
        assert sock.exists()

    def test_prediction_proxy_exists(self):
        """AI prediction proxy service must exist."""
        proxy = BASE_DIR / "backend" / "services" / "predictionProxy.js"
        assert proxy.exists()

    def test_prediction_proxy_targets_port_8000(self):
        """Prediction proxy must point to FastAPI on port 8000."""
        content = (BASE_DIR / "backend" / "services" / "predictionProxy.js").read_text(encoding="utf-8")
        assert "8000" in content


# ──────────────────────────────────────────────
# Project Governance Files Tests
# ──────────────────────────────────────────────


class TestGovernanceFiles:
    """Verify governance documentation files exist with content."""

    def test_rules_md_exists(self):
        """rules.md governance file must exist."""
        assert (BASE_DIR / "rules.md").exists()

    def test_security_md_exists(self):
        """security.md governance file must exist."""
        assert (BASE_DIR / "security.md").exists()

    def test_agent_md_exists(self):
        """agent.md 3-agent governance file must exist."""
        assert (BASE_DIR / "agent.md").exists()

    def test_gitignore_exists(self):
        """.gitignore must exist."""
        assert (BASE_DIR / ".gitignore").exists()

    def test_requirements_txt_exists(self):
        """requirements.txt must exist."""
        assert (BASE_DIR / "requirements.txt").exists()

    def test_final_audit_report_exists(self):
        """FINAL_AUDIT_REPORT.md must exist."""
        assert (BASE_DIR / "FINAL_AUDIT_REPORT.md").exists()
