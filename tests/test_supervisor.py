# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The supervisor is a privilege transport: an identifier in, bounded bytes out.
# Implements: D-123, AUTH-003, AUTH-004, AUTH-006, AUTH-014, AUTH-015, AUTH-016
#
# v0.2 P4. The supervisor performs registered fixed operations and nothing else. These cases
# hold the mechanism before any operation is enabled: a request carries no path, argument or
# environment; an unknown or not-yet-implemented identifier is refused; a target is never a
# symlink or a FIFO; output is bounded; a timeout stops the operation; only exit 0 succeeds;
# an untrusted executable never runs; the engine refuses any answer outside AUTH-015; and the
# supervisor package imports nothing from the engine.
#
# Unprivileged throughout. Operations are enabled only inside a test, by replacing the
# module's constant table; the production table enables nothing.
#
# meta:type="test"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries="python3,env,pwd,cat,false,yes,sleep"
# =============================================================================
"""v0.2 P4: supervisor mechanism, request refusals, bounds, timeouts, strict decoding."""
import copy
import inspect
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

from isedraf import coverage                                  # noqa: E402
from isedraf import fixedop                                   # noqa: E402
from isedraf.supervisor import contracts                      # noqa: E402
from isedraf.supervisor import perform                        # noqa: E402
from isedraf.supervisor import protocol                       # noqa: E402
from isedraf.supervisor import serve                          # noqa: E402

import check_privileged_operations as gate                    # noqa: E402

REGISTRY = json.loads((ROOT / "scripts" / "ci" / "privileged_operations.json")
                      .read_text(encoding="utf-8"))
# IQ-059: a test that needs an operation the supervisor cannot perform takes it from the
# registry at run time - registered, and absent from the contract table - never a name that
# a later slice will implement, which once sent a real supervisor to this machine's files.
UNIMPLEMENTED = sorted(o["operation_id"] for o in REGISTRY["operations"]
                       if o["operation_id"] not in contracts.CONTRACTS)[0]


def file_contract(target="/etc/shadow", bound=1048576, timeout=10):
    return {"performer": contracts.PERFORM_READ_REGULAR_FILE, "status": contracts.IMPLEMENTED,
            "targets": [target], "fixed_executable": None, "fixed_argv": [],
            "output_bound_bytes": bound, "timeout_seconds": timeout,
            "env_policy": "NOT_APPLICABLE", "cwd_policy": "NOT_APPLICABLE",
            "stdin_policy": "NOT_APPLICABLE", "exit_status_policy": "NOT_APPLICABLE"}


def exec_contract(executable, argv=(), bound=1048576, timeout=10):
    return {"performer": contracts.PERFORM_FIXED_EXECUTABLE, "status": contracts.IMPLEMENTED,
            "targets": ["the output of the fixed executable"],
            "fixed_executable": executable, "fixed_argv": list(argv),
            "output_bound_bytes": bound, "timeout_seconds": timeout,
            "env_policy": "CLEAN_FIXED", "cwd_policy": "ROOT_DIR", "stdin_policy": "DEVNULL",
            "exit_status_policy": "ZERO_ONLY_SUCCEEDS"}


def tool(name):
    for directory in ("/usr/bin", "/bin"):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            return path
    raise unittest.SkipTest("%s is not installed" % name)


def enable(table):
    return mock.patch.object(contracts, "CONTRACTS", table)


def assert_auth015(case, res):
    case.assertEqual(sorted(res), sorted(protocol.FIELDS))
    case.assertEqual(sorted(res["status_metadata"]), sorted(protocol.METADATA))
    case.assertIn(res["status"], protocol.STATUSES)
    case.assertEqual(res["status_metadata"]["byte_count"], len(res["bytes"]))


class Host(unittest.TestCase):

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-supervisor-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / "etc").mkdir()
        patcher = mock.patch.object(contracts, "HOST_ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)

    def shadow(self, data):
        path = self.root / "etc" / "shadow"
        path.write_bytes(data)
        return path


class OnlyTheFirstSliceIsEnabled(unittest.TestCase):
    """AUTH-025 as amended (D-124): the enabled operations are the validated ones and, at
    most, the one next candidate under validation - never anything else."""

    def test_the_production_table_enables_only_validated_or_next_candidate(self):
        admission = gate.admission_record()
        enabled = [o for o, c in contracts.CONTRACTS.items()
                   if c["status"] == contracts.IMPLEMENTED]
        allowed = set(admission["validated"]) | {admission["next_candidate"]}
        self.assertTrue(set(enabled) <= allowed, (enabled, allowed))
        self.assertIn("read_shadow_v1", enabled)

    def test_a_planned_operation_is_refused_although_it_has_a_performer(self):
        planned = dict(contracts.CONTRACTS["read_shadow_v1"], status="PLANNED")
        with enable({"read_shadow_v1": planned}):
            res = perform.perform("read_shadow_v1")
        assert_auth015(self, res)
        self.assertEqual(res["status"], protocol.REFUSED)
        self.assertEqual(res["stderr_bytes"], b"NOT_ENABLED")
        self.assertEqual(res["bytes"], b"")

    def test_an_unknown_operation_is_refused(self):
        res = perform.perform("read_everything_v1")
        self.assertEqual((res["status"], res["stderr_bytes"]),
                         (protocol.REFUSED, b"UNKNOWN_OPERATION"))

    def test_a_registered_but_unimplemented_identifier_is_unknown_to_the_supervisor(self):
        res = perform.perform("read_authorized_keys_v1")
        self.assertEqual(res["status"], protocol.REFUSED)

    def test_supervisor_acquisition_is_admitted_now_that_an_operation_is_enabled(self):
        self.assertIn("SUPERVISOR_FIXED_OPERATION", coverage.MODES)


class NoCallerInput(unittest.TestCase):
    """AUTH-003: the only thing a caller can send is an identifier."""

    def test_the_entry_points_take_no_path_argument_or_environment(self):
        self.assertEqual(list(inspect.signature(perform.perform).parameters), ["operation_id"])
        self.assertEqual(list(inspect.signature(serve.serve).parameters),
                         ["request_fd", "response_fd"])

    def answers(self, *lines):
        with tempfile.TemporaryFile() as req, tempfile.TemporaryFile() as resp:
            req.write(b"".join(lines))
            req.seek(0)
            count = serve.serve(req.fileno(), resp.fileno())
            resp.seek(0)
            raw = resp.read()
        out = []
        while raw:
            (size,) = protocol.HEADER.unpack(raw[:4])
            out.append(json.loads(raw[4:4 + size].decode("ascii")))
            raw = raw[4 + size:]
        self.assertEqual(count, len(out))
        return out

    def test_injection_shapes_are_refused_and_end_the_session(self):
        for line in (b"read_shadow_v1 /etc/passwd\n",
                     b"/etc/shadow\n",
                     b"read_shadow_v1\x00/etc/passwd\n",
                     b'{"operation_id":"read_shadow_v1","path":"/etc/passwd"}\n',
                     b"PATH=/tmp read_shadow_v1\n",
                     b"read_shadow_v1;cat /etc/passwd\n",
                     b"read_shadow_v1 --target=/root\n",
                     b"READ_SHADOW_V1\n",
                     b"r" * 200 + b"_v1\n"):
            out = self.answers(line, b"read_everything_v1\n")
            self.assertEqual(len(out), 1, line)
            self.assertEqual(out[0]["status"], protocol.REFUSED, line)
            self.assertIsNone(out[0]["operation_id"], line)

    def test_a_partial_line_at_end_of_input_is_refused(self):
        out = self.answers(b"read_shadow_v1")
        self.assertEqual((len(out), out[0]["status"]), (1, protocol.REFUSED))

    def test_each_valid_line_gets_exactly_one_answer(self):
        # The enabled operation reads under an empty fixture root, never this host.
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty, True)
        with mock.patch.object(contracts, "HOST_ROOT", empty):
            out = self.answers(b"read_shadow_v1\n", b"read_everything_v1\n")
        self.assertEqual([o["operation_id"] for o in out],
                         ["read_shadow_v1", "read_everything_v1"])

    def test_the_engine_cannot_encode_anything_but_an_identifier(self):
        for bad in ("read_shadow_v1 /etc/passwd", "/etc/shadow", "read_shadow", "", None,
                    "read_shadow_v0", "Read_shadow_v1"):
            with self.assertRaises(protocol.ProtocolError):
                protocol.encode_request(bad)


class ReadRegularFile(Host):

    def test_an_enabled_read_returns_the_bytes_and_nothing_else(self):
        self.shadow(b"root:!:19000:0:99999:7:::\n")
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        assert_auth015(self, res)
        self.assertEqual(res["status"], protocol.COMPLETED)
        self.assertEqual(res["bytes"], b"root:!:19000:0:99999:7:::\n")
        self.assertEqual(res["status_metadata"], {"exit_code": None, "byte_count": 26})
        self.assertIsNone(res["stderr_bytes"])

    def test_a_symlinked_target_is_never_followed(self):
        secret = self.root / "elsewhere"
        secret.write_bytes(b"not the shadow file\n")
        os.symlink(str(secret), str(self.root / "etc" / "shadow"))
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["bytes"], res["stderr_bytes"]),
                         (protocol.FAILED, b"", b"ELOOP"))

    def test_a_fifo_target_fails_without_blocking(self):
        os.mkfifo(str(self.root / "etc" / "shadow"))
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["stderr_bytes"]), (protocol.FAILED, b"NOT_REGULAR"))

    def test_a_directory_target_fails(self):
        (self.root / "etc" / "shadow").mkdir()
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["stderr_bytes"]), (protocol.FAILED, b"NOT_REGULAR"))

    def test_an_absent_target_fails_as_enoent(self):
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["stderr_bytes"]), (protocol.FAILED, b"ENOENT"))
        self.assertEqual(fixedop.access_outcome(res), coverage.NOT_FOUND)

    @unittest.skipIf(os.geteuid() == 0, "root reads past file permissions")
    def test_an_unreadable_target_fails_as_eacces_for_the_unprivileged_supervisor(self):
        path = self.shadow(b"root:!:19000::::::\n")
        os.chmod(str(path), 0)
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["stderr_bytes"]), (protocol.FAILED, b"EACCES"))
        self.assertEqual(fixedop.access_outcome(res), coverage.PERMISSION_DENIED)

    def test_output_past_the_bound_is_truncated_and_returns_no_bytes(self):
        self.shadow(b"x" * 101)
        with enable({"read_shadow_v1": file_contract(bound=100)}):
            res = perform.perform("read_shadow_v1")
        assert_auth015(self, res)
        self.assertEqual((res["status"], res["bytes"]), (protocol.TRUNCATED, b""))
        self.assertEqual(fixedop.access_outcome(res), coverage.TRUNCATED)

    def test_output_at_the_bound_is_complete(self):
        self.shadow(b"x" * 100)
        with enable({"read_shadow_v1": file_contract(bound=100)}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], len(res["bytes"])), (protocol.COMPLETED, 100))

    def test_the_timeout_stops_the_read(self):
        self.shadow(b"x" * 10)
        clock = iter([0.0, 11.0, 12.0, 13.0])
        with enable({"read_shadow_v1": file_contract(timeout=10)}), \
                mock.patch.object(perform, "_elapsed", lambda: next(clock)):
            res = perform.perform("read_shadow_v1")
        self.assertEqual((res["status"], res["bytes"], res["stderr_bytes"]),
                         (protocol.FAILED, b"", b"TIMEOUT"))

    def test_the_target_is_the_contract_constant(self):
        self.shadow(b"shadow bytes\n")
        (self.root / "etc" / "passwd").write_bytes(b"passwd bytes\n")
        with enable({"read_shadow_v1": file_contract()}):
            res = perform.perform("read_shadow_v1")
        self.assertEqual(res["bytes"], b"shadow bytes\n")


class FixedExecutable(unittest.TestCase):

    def run_contract(self, contract):
        with enable({"probe_v1": contract}):
            res = perform.perform("probe_v1")
        assert_auth015(self, res)
        return res

    def test_the_environment_is_exactly_clean_fixed(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/tmp/x.so", "ISEDRAF_EVIL": "1"}):
            res = self.run_contract(exec_contract(tool("env")))
        self.assertEqual(res["status"], protocol.COMPLETED)
        lines = sorted(res["bytes"].decode("ascii").splitlines())
        self.assertEqual(lines, ["LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"])
        self.assertEqual(res["status_metadata"]["exit_code"], 0)

    def test_the_working_directory_is_root(self):
        res = self.run_contract(exec_contract(tool("pwd")))
        self.assertEqual(res["bytes"], b"/\n")

    def test_stdin_is_devnull(self):
        res = self.run_contract(exec_contract(tool("cat"), timeout=5))
        self.assertEqual((res["status"], res["bytes"]), (protocol.COMPLETED, b""))

    def test_a_nonzero_exit_fails_with_its_code(self):
        res = self.run_contract(exec_contract(tool("false")))
        self.assertEqual((res["status"], res["status_metadata"]["exit_code"], res["bytes"]),
                         (protocol.FAILED, 1, b""))
        self.assertEqual(fixedop.access_outcome(res, runs_executable=True), coverage.IO_ERROR)

    def test_oversized_output_is_truncated_and_stopped(self):
        res = self.run_contract(exec_contract(tool("yes"), bound=1000, timeout=10))
        self.assertEqual((res["status"], res["bytes"]), (protocol.TRUNCATED, b""))
        self.assertIsNone(res["status_metadata"]["exit_code"])

    def test_the_timeout_stops_the_executable(self):
        res = self.run_contract(exec_contract(tool("sleep"), argv=["30"], timeout=1))
        self.assertEqual((res["status"], res["status_metadata"]["exit_code"]),
                         (protocol.FAILED, None))

    def test_a_missing_executable_fails(self):
        res = self.run_contract(exec_contract("/nonexistent/isedraf-probe"))
        self.assertEqual((res["status"], res["stderr_bytes"]), (protocol.FAILED, b"ENOENT"))

    def test_an_executable_not_owned_by_the_trusted_owner_never_runs(self):
        workdir = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-exe-"))
        self.addCleanup(shutil.rmtree, str(workdir), True)
        marker = workdir / "ran"
        probe = workdir / "probe"
        probe.write_text("#!/bin/sh\n: > %s\n" % marker)
        os.chmod(str(probe), 0o755)
        with mock.patch.object(contracts, "EXECUTABLE_OWNER_UID", os.geteuid() + 1):
            res = self.run_contract(exec_contract(str(probe)))
        self.assertEqual((res["status"], res["stderr_bytes"]),
                         (protocol.FAILED, b"UNTRUSTED_EXECUTABLE"))
        self.assertFalse(marker.exists())

    def test_a_group_writable_executable_never_runs(self):
        workdir = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-exe-"))
        self.addCleanup(shutil.rmtree, str(workdir), True)
        marker = workdir / "ran"
        probe = workdir / "probe"
        probe.write_text("#!/bin/sh\n: > %s\n" % marker)
        os.chmod(str(probe), 0o775)
        with mock.patch.object(contracts, "EXECUTABLE_OWNER_UID", os.geteuid()):
            res = self.run_contract(exec_contract(str(probe)))
        self.assertEqual(res["stderr_bytes"], b"UNTRUSTED_EXECUTABLE")
        self.assertFalse(marker.exists())


class TheEngineDecodesStrictly(unittest.TestCase):

    def frame(self, **change):
        body = json.loads(protocol.encode_response(
            protocol.result("read_shadow_v1", protocol.COMPLETED, b"abc"))[4:].decode("ascii"))
        body.update(change)
        return json.dumps(body).encode("ascii")

    def test_a_valid_response_decodes(self):
        res = protocol.decode_response(self.frame(), "read_shadow_v1")
        self.assertEqual(res["bytes"], b"abc")

    def test_an_extra_field_is_refused(self):
        for field in ("collection_status", "parsed", "finding", "severity", "path"):
            with self.assertRaises(protocol.ProtocolError, msg=field):
                protocol.decode_response(self.frame(**{field: "COLLECTED"}), "read_shadow_v1")

    def test_an_unknown_status_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_response(self.frame(status="PASS"), "read_shadow_v1")

    def test_a_byte_count_mismatch_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_response(
                self.frame(status_metadata={"exit_code": None, "byte_count": 2}),
                "read_shadow_v1")

    def test_an_answer_for_another_operation_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_response(self.frame(), "read_sudoers_graph_v1")

    def test_bytes_on_a_failed_result_are_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_response(self.frame(status="TRUNCATED"), "read_shadow_v1")

    def test_extra_status_metadata_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_response(
                self.frame(status_metadata={"exit_code": None, "byte_count": 3, "uid": 0}),
                "read_shadow_v1")

    def test_an_oversized_frame_is_refused_before_it_is_read(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        req_r, req_w = os.pipe()
        self.addCleanup(os.close, req_r)
        self.addCleanup(os.close, req_w)
        os.write(w, protocol.HEADER.pack(protocol.RESPONSE_LIMIT + 1))
        os.close(w)
        with self.assertRaises(protocol.ProtocolError):
            fixedop.Channel(req_w, r).request("read_shadow_v1")


class TwoProcesses(unittest.TestCase):
    """The engine and the supervisor as separate processes, over two pipes."""

    @staticmethod
    def stop(proc):
        # A failed assertion must not leave the supervisor waiting on an open stdin.
        for stream in (proc.stdin, proc.stdout):
            if not stream.closed:
                stream.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)

    def test_a_request_crosses_the_boundary_and_an_unregistered_operation_is_refused(self):
        # Never read_shadow_v1 here: a separate process cannot be pointed at a fixture, and
        # a test never opens this machine's /etc/shadow. The in-process cases and the
        # launcher route test exercise the enabled operation against fixtures.
        code = ("import sys; sys.path.insert(0, %r); "
                "from isedraf.supervisor import serve; serve.serve(0, 1)" % str(ROOT / "lib"))
        proc = subprocess.Popen([sys.executable, "-IB", "-c", code], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, env={"LC_ALL": "C"})
        self.addCleanup(self.stop, proc)
        channel = fixedop.Channel(proc.stdin.fileno(), proc.stdout.fileno())
        self.assertNotIn(UNIMPLEMENTED, contracts.CONTRACTS)
        res = channel.request(UNIMPLEMENTED)
        self.assertEqual((res["status"], res["stderr_bytes"]),
                         (protocol.REFUSED, b"UNKNOWN_OPERATION"))
        self.assertEqual(fixedop.access_outcome(res), coverage.NOT_SUPPORTED)
        res = channel.request("read_everything_v1")
        self.assertEqual(res["status"], protocol.REFUSED)
        proc.stdin.close()
        proc.stdout.close()
        self.assertEqual(proc.wait(timeout=30), 0)


class TransportNotIntelligence(unittest.TestCase):

    def test_the_supervisor_imports_only_the_standard_library_and_itself(self):
        self.assertEqual(gate.supervisor_imports(ROOT / "lib" / "isedraf" / "supervisor"), [])

    def test_a_parser_import_in_the_supervisor_is_refused(self):
        pkg = pathlib.Path(tempfile.mkdtemp(prefix="isedraf-pkg-"))
        self.addCleanup(shutil.rmtree, str(pkg), True)
        (pkg / "perform.py").write_text("from isedraf.accounts import sources\n")
        (pkg / "other.py").write_text("from isedraf import hostio\nfrom . import x\n")
        problems = gate.supervisor_imports(pkg)
        self.assertEqual(len(problems), 3, problems)

    def test_the_code_contracts_equal_the_registry(self):
        self.assertEqual(gate.check_code_contracts(REGISTRY, contracts.CONTRACTS), [])

    def test_a_drifted_contract_is_refused(self):
        for field, value in (("output_bound_bytes", 1 << 24), ("targets", ["/etc/gshadow"]),
                             ("status", "PLANNED"), ("timeout_seconds", 120)):
            code = copy.deepcopy(contracts.CONTRACTS)
            code["read_shadow_v1"][field] = value
            self.assertTrue(gate.check_code_contracts(REGISTRY, code), field)

    def test_a_contract_without_a_registry_entry_is_refused(self):
        code = copy.deepcopy(contracts.CONTRACTS)
        code["read_everything_v1"] = file_contract("/")
        self.assertTrue(gate.check_code_contracts(REGISTRY, code))

    def test_an_implemented_registry_entry_needs_a_contract(self):
        registry = copy.deepcopy(REGISTRY)
        for op in registry["operations"]:
            if op["operation_id"] == UNIMPLEMENTED:
                op["status"] = "IMPLEMENTED"
        self.assertTrue(gate.check_code_contracts(registry, contracts.CONTRACTS))


if __name__ == "__main__":
    unittest.main()
