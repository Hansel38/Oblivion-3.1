#!/usr/bin/env python3
"""Verify that Visual Studio projects use the shared, architecture-aware vcpkg setup."""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NS = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}


class WindowsVcpkgProjectConfigTests(unittest.TestCase):
    def test_shared_vcpkg_props_exists_and_checks_all_dependencies(self):
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
                f"{relative} does not import the shared vcpkg properties",
            )

            project_text = project_path.read_text(encoding="utf-8-sig")
            self.assertIn(r"$(OblivionVcpkgInstalledDir)\include", project_text)
            self.assertIn(r"$(OblivionVcpkgInstalledDir)\lib", project_text)
            self.assertNotIn(r"$(VCPKG_ROOT)\installed\$(OblivionVcpkgTriplet)", project_text)

    def test_setup_script_installs_matching_architecture_triplets(self):
        script = ROOT / "tools" / "setup_windows_dependencies.ps1"
        self.assertTrue(script.is_file())
        content = script.read_text(encoding="utf-8")
        self.assertIn("x64-windows-static-md", content)
        self.assertIn("x86-windows-static-md", content)
        self.assertIn("openssl:$triplet", content)
        self.assertIn("yaml-cpp:$triplet", content)
        self.assertIn("SetEnvironmentVariable", content)


if __name__ == "__main__":
    unittest.main()
