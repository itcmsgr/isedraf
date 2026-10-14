# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: `sudo isedraf report` (AUTH-032): the root side reads and frames, never writes;
#          the reduced renderer verifies before it renders and accepts only what was framed.
# Implements: AUTH-032, AUTH-022, AUTH-021, D-50, STORE-024
#
# Unprivileged: a real DEV audit of a small fixture host makes the store, and the store's
# owner constants are this test's uid. Root, setpriv and systemd are proven on the lab corpus.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3"
# =============================================================================
"""AUTH-032: the read-only report route."""
import fcntl
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.path.insert(0, LIB)

from isedraf import cli, ledger, stateroot                            # noqa: E402
from isedraf.launcher import renderer, reportunit, store              # noqa: E402
from isedraf.supervisor import frame                                  # noqa: E402

HOST = {"etc/machine-id": "3f9a1c0b7d2e4a68b5c6d7e8f9a0b1c2\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
        "etc/group": "root:x:0:\n",
        "proc/sys/kernel/hostname": "fixturehost\n"}
UID, GID = os.getuid(), os.getgid()


def fingerprint(root):
    out = []
    for base, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(dirs + files):
            path = os.path.join(base, name)
            st = os.lstat(path)
            digest = ""
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
            out.append((os.path.relpath(path, root), st.st_mode, st.st_mtime_ns, digest))
    return out


class ReportRoute(unittest.TestCase):

    def setUp(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        host = os.path.join(base, "host")
        for rel, text in HOST.items():
            path = os.path.join(host, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.root = os.path.join(base, "root")
        with mock.patch.dict(os.environ, {"ISEDRAF_STATE_ROOT": self.root}):
            code = cli.cmd_audit(type("A", (), {"root": host})(), out=io.StringIO(),
                                 err=io.StringIO())
        self.assertIn(code, (0, 2))
        for patch in (mock.patch.object(store, "OWNER_UID", UID),
                      mock.patch.object(store, "OWNER_GID", GID)):
            patch.start()
            self.addCleanup(patch.stop)

    def snapshot_id(self):
        return ledger.read_records(self.root)[-1]["record_core"]["snapshot_id"]

    def items(self):
        return reportunit.acquire(self.root, UID)

    def render(self, data, fmt="markdown"):
        out, err = io.StringIO(), io.StringIO()
        return renderer.render(fmt, data, out, err), out.getvalue(), err.getvalue()

    # -- the root side reads exactly the ledger and the latest committed snapshot ------------

    def test_the_root_side_reads_the_ledger_and_the_d50_snapshot_only(self):
        names = sorted(i["name"].decode() for i in self.items())
        sid = self.snapshot_id()
        self.assertEqual(names[0], stateroot.LEDGER_SEGMENT)
        self.assertTrue(all(n.startswith("snapshots/%s/" % sid) for n in names[1:]))
        self.assertTrue(set(n.split("/", 2)[2] for n in names[1:]) <= set(store.BUNDLE_FILES))
        self.assertIn("snapshots/%s/manifest.json" % sid, names)

    def test_the_root_side_never_touches_the_store(self):
        before = fingerprint(self.root)
        self.items()
        with mock.patch.object(reportunit, "render_argv", return_value=["/bin/true"]):
            reportunit.run("markdown", self.root, io.StringIO(), engine_uid=UID)
        self.assertEqual(fingerprint(self.root), before)

    def test_an_undeclared_file_in_the_snapshot_is_refused(self):
        sid = self.snapshot_id()
        with open(os.path.join(self.root, "snapshots", sid, "notes.txt"), "w") as fh:
            fh.write("x")
        err = io.StringIO()
        self.assertEqual(reportunit.run("markdown", self.root, err, engine_uid=UID), 64)
        self.assertIn("REPORT_REFUSED", err.getvalue())

    def test_a_link_in_the_snapshot_is_never_followed(self):
        sid = self.snapshot_id()
        target = os.path.join(self.root, "snapshots", sid, "sections", "ssh.json")
        os.unlink(target)
        os.symlink("/etc/hostname", target)
        err = io.StringIO()
        self.assertEqual(reportunit.run("markdown", self.root, err, engine_uid=UID), 64)
        self.assertIn("REPORT_REFUSED", err.getvalue())

    def test_a_held_lock_is_66(self):
        fd = os.open(os.path.join(self.root, stateroot.LOCK_NAME), os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(reportunit.run("markdown", self.root, io.StringIO(), engine_uid=UID), 66)

    def test_a_non_conforming_or_missing_store_is_67_and_untouched(self):
        os.chmod(self.root, 0o755)
        self.assertEqual(reportunit.run("markdown", self.root, io.StringIO(), engine_uid=UID), 67)
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o755)
        os.chmod(self.root, 0o700)
        self.assertEqual(reportunit.run("markdown", self.root + "-absent", io.StringIO(),
                                        engine_uid=UID), 67)
        self.assertFalse(os.path.lexists(self.root + "-absent"))

    def test_a_store_without_a_committed_run_says_so(self):
        os.unlink(os.path.join(self.root, stateroot.LEDGER_SEGMENT))
        err = io.StringIO()
        self.assertEqual(reportunit.run("markdown", self.root, err, engine_uid=UID), 64)
        self.assertIn("no committed Full Audit run", err.getvalue())

    def test_the_renderer_command_is_the_engine_reduction_and_a_fixed_entry(self):
        argv = reportunit.render_argv("json")
        self.assertEqual(argv[:9], ["/usr/bin/setpriv", "--reuid=isedraf", "--regid=isedraf",
                                    "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                                    "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3"])
        self.assertEqual(argv[-1], "json")
        with self.assertRaises(ValueError):
            reportunit.render_argv("/tmp/x")

    # -- the renderer verifies before it renders -------------------------------------------

    def test_a_verified_store_renders_with_its_verification_scope(self):
        code, out, err = self.render(frame.encode(self.items()))
        self.assertIn(code, (0, 2), err)
        self.assertIn("ISEDRAF System Assurance Report", out)
        self.assertIn("**PASS**", out)
        self.assertIn("| Verification scope | the ledger chain and the reported snapshot", out)
        self.assertIn("`/var/lib/isedraf`", out)
        code, out, _err = self.render(frame.encode(self.items()), "json")
        self.assertEqual(json.loads(out)["identity_evidence"]["verification"]["scope"],
                         renderer.SCOPE)
        code, out, _err = self.render(frame.encode(self.items()), "html")
        self.assertIn("Verification scope", out)

    def tampered(self, suffix, change):
        items = self.items()
        for it in items:
            if it["name"].decode().endswith(suffix):
                it["content"] = change(it["content"])
                it["lstat"]["size"] = len(it["content"])
        return frame.encode(items)

    def test_a_tampered_section_renders_nothing(self):
        data = self.tampered("sections/ssh.json", lambda b: b.replace(b'"', b"'", 1))
        code, out, err = self.render(data)
        self.assertEqual((code, out), (64, ""))
        self.assertIn("EVIDENCE_VERIFICATION_FAILED", err)

    def test_a_tampered_ledger_renders_nothing(self):
        def bump(raw):
            record = json.loads(raw.decode().strip())
            record["record_core"]["sequence"] = 2
            return (json.dumps(record) + "\n").encode()
        code, out, err = self.render(self.tampered("segment-000001.jsonl", bump))
        self.assertEqual((code, out), (64, ""))
        self.assertIn("EVIDENCE_VERIFICATION_FAILED", err)

    def test_a_name_outside_the_bundle_is_refused(self):
        sid = self.snapshot_id()
        for name in (b"etc/shadow", ("snapshots/%s/../../ledger/x" % sid).encode(),
                     ("snapshots/%s/notes.txt" % sid).encode()):
            # Swapped in for a declared file, so the item bound is not what refuses it.
            items = [i for i in self.items() if not i["name"].endswith(b"sections/pam.json")]
            items.append(frame.item(frame.ENTRY, name, frame.READ_OK,
                                    {"mode": 0o100600, "uid": 0, "gid": 0, "size": 1}, b"x"))
            code, out, err = self.render(frame.encode(items))
            self.assertEqual((code, out), (64, ""), name)
            self.assertIn("does not read", err)

    def test_a_frame_beyond_the_item_bound_is_refused(self):
        items = self.items() + [frame.item(frame.ENTRY, b"etc/shadow", frame.READ_OK,
                                           {"mode": 0o100600, "uid": 0, "gid": 0, "size": 1},
                                           b"x")]
        code, out, err = self.render(frame.encode(items))
        self.assertEqual((code, out), (64, ""))
        self.assertIn("item", err)

    def test_a_frame_without_the_manifest_is_refused(self):
        items = [i for i in self.items() if not i["name"].endswith(b"manifest.json")]
        code, out, err = self.render(frame.encode(items))
        self.assertEqual((code, out), (64, ""))

    def test_a_malformed_frame_is_refused(self):
        code, out, err = self.render(b"not a frame")
        self.assertEqual((code, out), (64, ""))
        self.assertIn("frame is invalid", err)

    def test_the_renderer_leaves_no_temporary_files(self):
        before = set(os.listdir(tempfile.gettempdir()))
        self.render(frame.encode(self.items()))
        leftover = [n for n in set(os.listdir(tempfile.gettempdir())) - before
                    if n.startswith("isedraf-report-")]
        self.assertEqual(leftover, [])

    def test_the_whole_route_hands_the_frame_to_the_renderer_and_returns_its_code(self):
        entry = ("import sys; sys.path.insert(0, %r); from isedraf.launcher.renderer import main; "
                 "sys.exit(main(sys.argv[1:]))" % os.path.abspath(LIB))
        out_path = os.path.join(tempfile.mkdtemp(), "out")
        self.addCleanup(shutil.rmtree, os.path.dirname(out_path), True)
        saved = os.dup(1)
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            os.dup2(fd, 1)
            with mock.patch.object(reportunit, "render_argv",
                                   lambda fmt: [sys.executable, "-IB", "-c", entry, fmt]):
                code = reportunit.run("markdown", self.root, io.StringIO(), engine_uid=UID)
        finally:
            os.dup2(saved, 1)
            os.close(saved)
            os.close(fd)
        self.assertIn(code, (0, 2))
        with open(out_path) as fh:
            self.assertIn("Verification scope", fh.read())


if __name__ == "__main__":
    unittest.main()
