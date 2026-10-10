"""A real signed view set keeps same-key fork evidence separate from missing views and other keys."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from wireledger.lab import certificates, tls_server
from wireledger.ledger import append, canonical, make_checkpoint, verify
from wireledger.probe import observe
from wireledger.verification_set import compare_set

ROOT = Path(__file__).resolve().parents[1]


class HistoryComparisonSetAcceptance(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "wireledger", *map(str, args)], cwd=ROOT,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout.startswith("{") else result

    def browser_report(self, root, html, expected):
        if os.environ.get("WIRELEDGER_BROWSER_TESTS") != "1":
            return
        from playwright.sync_api import sync_playwright
        page_path = root / "captured-report.html"
        page_path.write_text(html)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(accept_downloads=True)
            requests = []
            page.on("request", lambda request: requests.append(request.url))
            selected = "divergent" if expected["same_key_divergence_found"] else "unverified"
            selected_count = sum(row["relation"] == selected for row in expected["pairs"])
            for width in (360, 1280):
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(page_path.as_uri())
                self.assertEqual(page.locator("h1").inner_text(), "Wireledger retained history consistency")
                summary = page.locator(".critical-summary").inner_text()
                self.assertIn(str(expected["verified_views"]) + " of " + str(expected["views_checked"]), summary)
                self.assertIn(str(expected["unverified_pairs"]) + " pairs unknown", summary)
                self.assertEqual(page.locator(".report-card:visible").count(), expected["pairs_checked"])
                self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
                page.locator(".report-scope summary").focus()
                page.keyboard.press("Enter")
                self.assertTrue(page.locator(".report-scope .scope").is_visible())
                self.assertIn("No divergence found is not absence proof", page.locator(".scope").inner_text())
                page.locator("#group").select_option(selected)
                self.assertEqual(page.locator(".report-card:visible").count(), selected_count)
                self.assertEqual(page.locator("#matches").inner_text(), f"{selected_count} of {expected['pairs_checked']} report rows shown")
                with page.expect_download() as event:
                    page.locator("#download").click()
                self.assertEqual(json.loads(Path(event.value.path()).read_text()), expected)
                with page.expect_download() as event:
                    page.locator("#download-view").click()
                static = Path(event.value.path()).read_text()
                self.assertIn("Other rows are omitted", static)
                self.assertIn("No divergence found is not absence proof", static)
                self.assertNotIn('id="report-data"', static)
                self.assertNotIn("<script", static)
                self.assertEqual(page.locator("svg,img,iframe").count(), 0)
                self.assertIsNone(page.evaluate("window.untrustedExecuted"))
                artifacts = os.environ.get("WIRELEDGER_BROWSER_ARTIFACTS")
                if artifacts and width == 360:
                    destination = Path(artifacts)
                    destination.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(destination / ("wireledger-set-partial.png" if expected['unverified_pairs'] else "wireledger-set-divergent.png")), full_page=True)
            self.assertTrue(all(url.startswith(("file:", "blob:")) for url in requests))
            browser.close()

    def test_signed_prefix_identical_fork_and_missing_views_preserve_scope_and_input_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # All keys are newly generated fixture-only keys, never account/service keys.
            key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
            for name, value in (("trusted.pub", key), ("other.pub", other)):
                (root / name).write_bytes(value.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            paths = {name: root / (name + ".jsonl") for name in ("prefix", "left", "same", "right", "other")}
            ca, variants = certificates(root); cert, server_key = variants[0]
            with tls_server(cert, server_key) as port:
                first = observe("localhost", port, connect_ip="127.0.0.1", cafile=str(ca), vantage="fixture")
                paths["prefix"].write_bytes(b""); append(paths["prefix"], key, first)
                for name in ("left", "right"):
                    paths[name].write_bytes(paths["prefix"].read_bytes())
                    append(paths[name], key, observe("localhost", port, connect_ip="127.0.0.1", cafile=str(ca), vantage=name))
                paths["same"].write_bytes(paths["left"].read_bytes())
                paths["other"].write_bytes(b""); append(paths["other"], other, first)
            pin = root / "prefix.pin"
            pin.write_bytes(canonical(make_checkpoint(verify(paths["prefix"], key.public_key()), key)))
            value = {"format": "wireledger-history-view-set/v1", "views": [
                {"id": name, "history": paths[name].name, "public_key": "other.pub" if name == "other" else "trusted.pub",
                 "checkpoint": None if name == "other" else pin.name}
                for name in ("prefix", "left", "same", "right", "other")]}
            manifest = root / "views.json"; manifest.write_text(json.dumps(value))
            originals = {path: path.read_bytes() for path in [*paths.values(), pin, manifest, root / "trusted.pub", root / "other.pub"]}
            report = self.cli("compare-set", manifest, expected=2)
            self.assertTrue(report["all_verified"])
            self.assertTrue(report["same_key_divergence_found"])
            self.assertEqual((report["pairs_checked"], report["same_key_pairs_compared"], report["unverified_pairs"]), (10, 6, 0))
            pairs = {(row["left"], row["right"]): row for row in report["pairs"]}
            self.assertEqual(pairs["prefix", "left"]["relation"], "left-prefix")
            self.assertEqual(pairs["left", "same"]["relation"], "identical")
            self.assertEqual((pairs["left", "right"]["relation"], pairs["left", "right"]["first_divergence"]), ("divergent", 2))
            self.assertEqual(pairs["left", "other"]["relation"], "different-public-keys")
            native = self.cli("compare", paths["left"], paths["right"], "--left-key", root / "trusted.pub",
                              "--right-key", root / "trusted.pub", expected=2)
            self.assertEqual(native["history"]["first_divergence"], pairs["left", "right"]["first_divergence"])
            independent = self.cli("verify-set", manifest)
            self.assertEqual(independent["views"], report["views"])
            html = self.cli("compare-set", manifest, "--html", expected=2).stdout
            self.assertIn("Wireledger retained history consistency", html)
            self.assertNotIn("localhost", html)
            self.assertNotIn(str(root), html)
            self.assertNotIn("BEGIN CERTIFICATE", html)
            self.browser_report(root, html, report)
            paths["right"].write_bytes(originals[paths["right"]] + b"invalid\n")
            partial = self.cli("compare-set", manifest, expected=2)
            self.assertFalse(partial["all_verified"])
            self.assertFalse(partial["same_key_divergence_found"])
            self.assertEqual(partial["unverified_pairs"], 4)
            self.assertIsNone(next(row for row in partial["views"] if row["id"] == "right")["records"])
            self.assertEqual(next(row for row in partial["views"] if row["id"] == "left")["records"], 2)
            self.browser_report(root, self.cli("compare-set", manifest, "--html", expected=2).stdout, partial)
            paths["right"].write_bytes(originals[paths["right"]])
            invalid = deepcopy(value); invalid["views"][-1]["unexpected"] = True
            with patch("wireledger.verification_set.load_public", side_effect=AssertionError("late rows must validate before opens")):
                with self.assertRaises(ValueError):
                    compare_set(invalid, root)
                with self.assertRaises(ValueError):
                    compare_set({"format": value["format"], "views": value["views"][:1]}, root)
            hostile = deepcopy(value)
            hostile["views"][-1]["id"] = '<svg onload="window.untrustedExecuted=1">'
            manifest.write_text(json.dumps(hostile))
            refused = self.cli("compare-set", manifest, "--html", expected=1)
            self.assertNotIn("<!doctype html>", refused.stdout.lower())
            manifest.write_bytes(originals[manifest])
            code = ("from unittest.mock import patch;from wireledger.__main__ import main\n"
                    "with patch('socket.getaddrinfo',side_effect=AssertionError('DNS forbidden')),"
                    "patch('wireledger.ledger.load_private',side_effect=AssertionError('signing key forbidden')),"
                    "patch('wireledger.__main__.load_private',side_effect=AssertionError('signing key forbidden')):"
                    "raise SystemExit(main(" + repr(["compare-set", str(manifest)]) + "))")
            offline = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(offline.returncode, 2, offline.stdout + offline.stderr)
            self.assertEqual(json.loads(offline.stdout), report)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)
