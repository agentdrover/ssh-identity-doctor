"""Performance budget test for scan (sdd-spec §11 NFR-001).

NFR-001: "A normal scan of up to 100 public identities and 500 config entries
shall complete within 10 seconds, excluding a timed-out optional adapter."
"""

from __future__ import annotations

import time

from ssh_id_doctor.domain import CoverageState
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator

from .conftest import DeterministicKeygen, FakeAgent, PerfHomeFixture

# Constant referencing NFR-001 specification limit
NFR_001_SCAN_BUDGET_SECONDS: float = 10.0


def test_the_generator_builds_exactly_the_declared_home(perf_home: PerfHomeFixture) -> None:
    """AC-2: Verify synthetic HOME generator produces declared count on disk.

    - Exactly 100 .pub files
    - Exactly 500 Host blocks across config and included files
    - No private key files created
    - No external programs invoked
    """
    home = perf_home.home
    ssh_dir = home / ".ssh"

    pub_files = list(ssh_dir.rglob("*.pub"))
    assert len(pub_files) == 100, f"Expected exactly 100 .pub files, found {len(pub_files)}"
    assert perf_home.num_pub_files == 100

    # Ensure no private key material or private key files exist
    for f in ssh_dir.rglob("*"):
        if f.is_file():
            assert not f.name.startswith("id_") or f.name.endswith(".pub"), (
                f"Unexpected private key candidate: {f}"
            )
            data = f.read_bytes()
            assert b"PRIVATE KEY" not in data, f"File {f} contains private key header"

    # Count Host blocks in config files
    orchestrator = ScanOrchestrator(
        keygen=DeterministicKeygen(),
        agent_adapter=FakeAgent(),
    )
    doc = orchestrator._config.parse_file(ssh_dir / "config")
    assert len(doc.host_blocks) == 500, (
        f"Expected exactly 500 Host blocks parsed, found {len(doc.host_blocks)}"
    )
    assert perf_home.num_host_blocks == 500


def test_scan_of_100_identities_and_500_entries_fits_the_budget(
    perf_home: PerfHomeFixture,
) -> None:
    """AC-1: Scan of 100 identities and 500 config entries completes within 10s budget.

    - Uses fake keygen and agent (no external subprocesses)
    - check_github=False
    - Measures scan time under time.perf_counter
    - Verifies snapshot has 100 identities and 500 host blocks parsed
    - Measured time fits within NFR_001_SCAN_BUDGET_SECONDS (10.0s)
    """
    home = perf_home.home
    ssh_dir = home / ".ssh"
    config_path = ssh_dir / "config"

    orchestrator = ScanOrchestrator(
        keygen=DeterministicKeygen(),
        agent_adapter=FakeAgent(),
    )

    opts = OrchestratorOptions(
        home=home,
        ssh_dir=ssh_dir,
        config_path=config_path,
        check_agent=True,
        check_github=False,
    )

    start_time = time.perf_counter()
    snapshot = orchestrator.run(opts)
    elapsed_time = time.perf_counter() - start_time

    # Verification of completeness: 100 identities discovered
    assert len(snapshot.identities) == 100, (
        f"Expected 100 identities in snapshot, got {len(snapshot.identities)}"
    )

    # Verification of config coverage detail naming 500 host blocks parsed
    config_sources = [s for s in snapshot.sources if s.source == "config"]
    assert len(config_sources) == 1
    assert config_sources[0].state is CoverageState.AVAILABLE
    assert config_sources[0].detail == "500 host blocks parsed", (
        f"Expected '500 host blocks parsed', got {config_sources[0].detail!r}"
    )

    # Verification of host bindings parsed: 500 host blocks
    assert len(snapshot.host_bindings) == 500, (
        f"Expected 500 host bindings in snapshot, got {len(snapshot.host_bindings)}"
    )

    # Budget assertion referencing NFR-001 with measured elapsed time in message
    assert elapsed_time <= NFR_001_SCAN_BUDGET_SECONDS, (
        f"NFR-001 budget exceeded: scan took {elapsed_time:.3f}s, "
        f"budget is {NFR_001_SCAN_BUDGET_SECONDS:.1f}s"
    )
