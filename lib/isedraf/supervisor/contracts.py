# =============================================================================
# ISEDRAF — Linux Host Assurance, State Delta & Evidence Engine (codename)
# =============================================================================
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS <contact@itcms.gr>
#
# Purpose: The fixed operation contracts the supervisor can perform, as constants.
# Implements: D-123, AUTH-004, AUTH-008, AUTH-014
#
# Every value here is a constant of the package. Nothing is read from configuration, the
# environment or the caller. scripts/ci/check_privileged_operations.py requires each
# contract to equal its entry in scripts/ci/privileged_operations.json field for field,
# status included, so the code and the registry cannot drift apart.
#
# A contract is ENABLED only when its status is IMPLEMENTED. The supervisor refuses every
# other identifier, including one that has a contract and a performer here but is still
# PLANNED in the registry.
#
# meta:type="library"
# meta:owner="Antonios Voulvoulis / ITCMS"
# meta:stability="EXPERIMENTAL"
# meta:privilege="unprivileged"
# meta:mutates="none"
# meta:binaries=""
# =============================================================================
"""Fixed operation contracts: constants, mirrored by the registry gate."""

IMPLEMENTED = "IMPLEMENTED"

# Every target is joined under HOST_ROOT. It is "/" and no runtime path changes it; the
# tests replace the module constant to read fixtures.
HOST_ROOT = "/"
# A fixed executable must be a regular file owned by this uid and writable by no one else.
EXECUTABLE_OWNER_UID = 0

# AUTH-014 CLEAN_FIXED: the EXEC-011 environment and nothing else.
EXEC_ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
EXEC_CWD = "/"

PERFORM_READ_REGULAR_FILE = "read_regular_file"
PERFORM_READ_FIXED_TREE = "read_fixed_tree"
PERFORM_FIXED_EXECUTABLE = "fixed_executable"

# The registry fields a code contract must equal (check_privileged_operations.py).
MIRRORED = ("status", "targets", "fixed_executable", "fixed_argv", "output_bound_bytes",
            "timeout_seconds", "env_policy", "cwd_policy", "stdin_policy",
            "exit_status_policy")

CONTRACTS = {
    "read_shadow_v1": {
        "performer": PERFORM_READ_REGULAR_FILE,
        "status": IMPLEMENTED,
        "targets": ["/etc/shadow"],
        "fixed_executable": None,
        "fixed_argv": [],
        "output_bound_bytes": 1048576,
        "timeout_seconds": 10,
        "env_policy": "NOT_APPLICABLE",
        "cwd_policy": "NOT_APPLICABLE",
        "stdin_policy": "NOT_APPLICABLE",
        "exit_status_policy": "NOT_APPLICABLE",
    },
    # AUTH-029: the fixed surface, as constants of the package. The registry's targets say
    # the same in words; root_file and directory are the only paths the performer joins.
    "read_sudoers_graph_v1": {
        "performer": PERFORM_READ_FIXED_TREE,
        "status": IMPLEMENTED,
        "targets": ["/etc/sudoers", "the listing of /etc/sudoers.d",
                    "each non-symlink regular directory entry directly enumerated in "
                    "/etc/sudoers.d"],
        "root_file": "/etc/sudoers",
        "directory": "/etc/sudoers.d",
        "member_bound_bytes": 1048576,
        "max_entries": 1024,
        "fixed_executable": None,
        "fixed_argv": [],
        "output_bound_bytes": 4194304,
        "timeout_seconds": 10,
        "env_policy": "NOT_APPLICABLE",
        "cwd_policy": "NOT_APPLICABLE",
        "stdin_policy": "NOT_APPLICABLE",
        "exit_status_policy": "NOT_APPLICABLE",
    },
    # AUTH-030: the same fixed-tree acquisition over /etc/ssh. Declared configuration only:
    # no executable, never sshd.
    "read_sshd_declared_config_v1": {
        "performer": PERFORM_READ_FIXED_TREE,
        "status": IMPLEMENTED,
        "targets": ["/etc/ssh/sshd_config", "the listing of /etc/ssh/sshd_config.d",
                    "each non-symlink regular directory entry directly enumerated in "
                    "/etc/ssh/sshd_config.d"],
        "root_file": "/etc/ssh/sshd_config",
        "directory": "/etc/ssh/sshd_config.d",
        "member_bound_bytes": 1048576,
        "max_entries": 1024,
        "fixed_executable": None,
        "fixed_argv": [],
        "output_bound_bytes": 4194304,
        "timeout_seconds": 10,
        "env_policy": "NOT_APPLICABLE",
        "cwd_policy": "NOT_APPLICABLE",
        "stdin_policy": "NOT_APPLICABLE",
        "exit_status_policy": "NOT_APPLICABLE",
    },
    # AUTH-031: the fixed executable and its constant argv, nothing else - no -C, -f or -o,
    # and no input. The global effective configuration only; stdout returned unparsed.
    "resolve_sshd_effective_config_v1": {
        "performer": PERFORM_FIXED_EXECUTABLE,
        "status": IMPLEMENTED,
        "targets": ["the stdout of the fixed executable below: the global effective "
                    "configuration, no -C connection context"],
        "fixed_executable": "/usr/sbin/sshd",
        "fixed_argv": ["-T"],
        "output_bound_bytes": 1048576,
        "timeout_seconds": 30,
        "env_policy": "CLEAN_FIXED",
        "cwd_policy": "ROOT_DIR",
        "stdin_policy": "DEVNULL",
        "exit_status_policy": "ZERO_ONLY_SUCCEEDS",
    },
}


def enabled(operation_id):
    """The contract for an identifier the supervisor may perform, else None."""
    contract = CONTRACTS.get(operation_id)
    if contract is None or contract["status"] != IMPLEMENTED:
        return None
    return contract
