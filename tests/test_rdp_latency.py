import shutil
import subprocess
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

ITERATIONS = 50
MAX_P95_OVERHEAD_MS = 100


def _percentile(sorted_values: list[float], p: float) -> float:
    """Return the p-th percentile from a pre-sorted list of values."""
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_values):
        return sorted_values[f]
    return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])


def _measure_connection_time(
    cmd: list[str],
    timeout: int,
) -> float:
    """Run an xfreerdp command and return elapsed wall-clock seconds."""
    start = time.time()
    subprocess.run(cmd, capture_output=True, timeout=timeout)
    return time.time() - start


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
@pytest.mark.skip(
    reason="RDP latency test requires full E2E infrastructure and manual measurement"
)
class Test:
    def test_warpgate_rdp_overhead_p95(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        rdp_port = processes.start_rdp_server()
        wait_port(rdp_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            rdp_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRDPOptions(
                            kind="Rdp",
                            host="localhost",
                            port=rdp_port,
                            username="warpgate-rdp-test",
                            password="test",
                        )
                    ),
                )
            )
            api.add_target_role(rdp_target.id, role.id)

        # Warm up: one connection through Warpgate and one direct
        subprocess.run(
            [
                "xfreerdp",
                f"/v:localhost:{shared_wg.rdp_port}",
                f"/u:{user.username}#{rdp_target.name}",
                "/p:123",
                "/cert:ignore",
                "+auth-only",
            ],
            capture_output=True,
            timeout=timeout,
        )
        subprocess.run(
            [
                "xfreerdp",
                f"/v:localhost:{rdp_port}",
                "/u:warpgate-rdp-test",
                "/p:test",
                "/cert:ignore",
                "+auth-only",
            ],
            capture_output=True,
            timeout=timeout,
        )

        # Measure connection time through Warpgate
        warpgate_times: list[float] = []
        for _ in range(ITERATIONS):
            elapsed = _measure_connection_time(
                [
                    "xfreerdp",
                    f"/v:localhost:{shared_wg.rdp_port}",
                    f"/u:{user.username}#{rdp_target.name}",
                    "/p:123",
                    "/cert:ignore",
                    "+auth-only",
                ],
                timeout=timeout,
            )
            warpgate_times.append(elapsed)

        # Measure direct connection time to xrdp
        direct_times: list[float] = []
        for _ in range(ITERATIONS):
            elapsed = _measure_connection_time(
                [
                    "xfreerdp",
                    f"/v:localhost:{rdp_port}",
                    "/u:warpgate-rdp-test",
                    "/p:test",
                    "/cert:ignore",
                    "+auth-only",
                ],
                timeout=timeout,
            )
            direct_times.append(elapsed)

        # Compute per-iteration overhead
        overheads = [
            w - d for w, d in zip(warpgate_times, direct_times, strict=True)
        ]
        overheads.sort()

        p95_overhead_s = _percentile(overheads, 95)
        p95_overhead_ms = p95_overhead_s * 1000

        warpgate_times.sort()
        direct_times.sort()

        print(f"\n--- RDP Latency Benchmark ({ITERATIONS} iterations) ---")
        print(f"Warpgate p50: {_percentile(warpgate_times, 50) * 1000:.1f}ms")
        print(f"Warpgate p95: {_percentile(warpgate_times, 95) * 1000:.1f}ms")
        print(f"Direct   p50: {_percentile(direct_times, 50) * 1000:.1f}ms")
        print(f"Direct   p95: {_percentile(direct_times, 95) * 1000:.1f}ms")
        print(f"Overhead p95: {p95_overhead_ms:.1f}ms")
        print(f"Threshold:    {MAX_P95_OVERHEAD_MS}ms")

        assert p95_overhead_ms <= MAX_P95_OVERHEAD_MS, (
            f"Warpgate RDP overhead at p95 is {p95_overhead_ms:.1f}ms, "
            f"exceeds {MAX_P95_OVERHEAD_MS}ms threshold"
        )
