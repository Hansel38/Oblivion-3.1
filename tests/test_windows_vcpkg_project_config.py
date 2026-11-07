#!/usr/bin/env python3
"""Verify shared vcpkg configuration for the Windows Visual Studio projects."""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NS = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}


class WindowsVcpkgProjectConfigTests(unittest.TestCase):
    def test_shared_vcpkg_props_exists_and_checks_dependencies(self):
        props_path = ROOT / "common" / "OblivionVcpkg.props"
        self.assertTrue(props_path.is_file())
        root = ET.parse(props_path).getroot()
        names = {element.tag.rsplit("}", 1)[-1] for element in root.iter()}

        self.assertIn("OblivionVcpkgRoot", names)
        self.assertIn("OblivionVcpkgInstalledDir", names)
        self.assertIn("Target", names)
        self.assertIn("Error", names)

        content = props_path.read_text(encoding="utf-8")
        self.assertIn(r"openssl\ssl.h", content)
        self.assertIn("libssl.lib", content)
        self.assertIn("libcrypto.lib", content)
        self.assertIn("yaml-cpp.lib", content)
        self.assertIn("setup_windows_dependencies.ps1", content)

    def test_client_and_server_import_shared_dependency_props(self):
        for relative in ("client/client.vcxproj", "server/server.vcxproj"):
            project_path = ROOT / relative
            project = ET.parse(project_path).getroot()
            imports = [node.attrib.get("Project", "") for node in project.findall("msb:Import", NS)]

            self.assertTrue(
                any(path.endswith(r"common\OblivionVcpkg.props") for path in imports),
                f"{relative} does not import shared vcpkg properties",
            )

            content = project_path.read_text(encoding="utf-8-sig")
            self.assertIn(r"$(OblivionVcpkgInstalledDir)\include", content)
            self.assertIn(r"$(OblivionVcpkgInstalledDir)\lib", content)
            self.assertNotIn(r"$(VCPKG_ROOT)\installed\$(OblivionVcpkgTriplet)", content)

    def test_win32_uses_x86_triplet_and_has_repository_root_fallback(self):
        for relative in ("client/client.vcxproj", "server/server.vcxproj"):
            content = (ROOT / relative).read_text(encoding="utf-8-sig")
            self.assertIn(
                """<OblivionVcpkgTriplet Condition="'$(Platform)'=='Win32'">x86-windows-static-md</OblivionVcpkgTriplet>""",
                content,
            )

        props = (ROOT / "common" / "OblivionVcpkg.props").read_text(encoding="utf-8")
        self.assertIn("OblivionVcpkgRepositoryRoot", props)
        self.assertIn("installed\\$(OblivionVcpkgTriplet)\\include\\openssl\\ssl.h", props)
        self.assertIn("Checked: $(OblivionVcpkgInstalledDir)", props)

    def test_setup_script_verifies_installed_headers_and_libraries(self):
        content = (ROOT / "tools" / "setup_windows_dependencies.ps1").read_text(encoding="utf-8")
        for required in (
            'include\\openssl\\ssl.h',
            'lib\\libssl.lib',
            'lib\\libcrypto.lib',
            'lib\\yaml-cpp.lib',
            "Dependency installation for",
            "PathType Leaf",
        ):
            self.assertIn(required, content)

    def test_public_network_reporter_header_forward_declares_tls_types(self):
        header = (ROOT / "client" / "include" / "network_reporter.h").read_text(encoding="utf-8")
        self.assertNotIn("#include <openssl/ssl.h>", header)
        self.assertIn("typedef struct ssl_ctx_st SSL_CTX;", header)
        self.assertIn("typedef struct ssl_st SSL;", header)

        tls_transport = (ROOT / "common" / "tls_transport.h").read_text(encoding="utf-8")
        self.assertIn("#include <openssl/ssl.h>", tls_transport)

    def test_setup_script_installs_matching_x86_and_x64_triplets(self):
        script_path = ROOT / "tools" / "setup_windows_dependencies.ps1"
        self.assertTrue(script_path.is_file())
        content = script_path.read_text(encoding="utf-8")

        for required in (
            "x64-windows-static-md",
            "x86-windows-static-md",
            "openssl:$triplet",
            "yaml-cpp:$triplet",
            "SetEnvironmentVariable",
        ):
            self.assertIn(required, content)


if __name__ == "__main__":
    unittest.main()
