"""Exercise launcher discovery/quoting and non-destructive installation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="setoken test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "Signed App $literal.app"
        resources = self.app / "Contents/Resources"
        executable = self.app / "Contents/MacOS/SecureEnclaveToken"
        resources.mkdir(parents=True)
        executable.parent.mkdir()
        executable.write_text('#!/bin/sh\nprintf "<%s>\\n" "$@"\ncat\nexit "${TEST_EXIT_CODE:-0}"\n')
        executable.chmod(0o755)
        for name in ("setoken", "install-setoken"):
            shutil.copy2(ROOT / "Scripts" / name, resources / name)
        self.launcher = resources / "setoken"
        self.installer = resources / "install-setoken"
        self.bin = self.root / "user bin"
        self.env = dict(os.environ)
        self.env.pop("SETOKEN_APP", None)

    def run_tool(self, *args, **kwargs):
        return subprocess.run([str(arg) for arg in args], input=kwargs.pop("input", ""),
                              text=True, capture_output=True, env=kwargs.pop("env", self.env), **kwargs)

    def test_bundle_arguments_stdin_and_exit_status(self):
        self.env["TEST_EXIT_CODE"] = "37"
        result = self.run_tool(self.launcher, "req", "a key", "-cn", "literal `text` $(text)", input="stdin data\n")
        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, "<cli>\n<req>\n<a key>\n<-cn>\n<literal `text` $(text)>\nstdin data\n")
        self.assertEqual(result.stderr, "")

    def test_installed_symlink_and_idempotent_install(self):
        for _ in range(2):
            result = self.run_tool(self.installer, "--bin-dir", self.bin)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_tool(self.bin / "setoken", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "<cli>\n<--help>\n")
        # Follow relative symlinks too.
        (self.bin / "relative").symlink_to("setoken")
        self.assertEqual(self.run_tool(self.bin / "relative", "keys").stdout, "<cli>\n<keys>\n")

    def test_existing_command_is_preserved(self):
        self.bin.mkdir()
        command = self.bin / "setoken"
        command.write_text("existing command\n")
        result = self.run_tool(self.installer, "--bin-dir", self.bin)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(command.read_text(), "existing command\n")

    def test_app_override_and_missing_app(self):
        self.env["SETOKEN_APP"] = str(self.app)
        result = self.run_tool(ROOT / "Scripts/setoken", "keys")
        self.assertEqual(result.stdout, "<cli>\n<keys>\n")
        self.env["SETOKEN_APP"] = str(self.root / "missing.app")
        result = self.run_tool(self.launcher, "keys")
        self.assertEqual(result.returncode, 127)
        self.assertIn("cannot find", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_installer_explicit_app_and_incomplete_arguments(self):
        result = self.run_tool(ROOT / "Scripts/install-setoken", "--app", self.app, "--bin-dir", self.bin)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_tool(self.installer, "--app").returncode, 64)


if __name__ == "__main__":
    unittest.main()
