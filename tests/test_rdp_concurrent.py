import shutil
import subprocess
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

CONCURRENT_CONNECTIONS = 50
PROCESS_TIMEOUT = 60


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
@pytest.mark.skip(reason="Concurrent RDP test requires full E2E infrastructure")
class Test:
    def test_concurrent_rdp_connections(
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

        children = []
        for _ in range(CONCURRENT_CONNECTIONS):
            child = subprocess.Popen(
                [
                    "xfreerdp",
                    f"/v:localhost:{shared_wg.rdp_port}",
                    f"/u:{user.username}#{rdp_target.name}",
                    "/p:123",
                    "/cert:ignore",
                    "+auth-only",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            children.append(child)

        for child in children:
            child.wait(timeout=PROCESS_TIMEOUT)

        failed = [i for i, child in enumerate(children) if child.returncode != 0]
        assert len(failed) == 0, (
            f"{len(failed)}/{CONCURRENT_CONNECTIONS} connections failed: indices {failed}"
        )

        time.sleep(2)

        with admin_client(url) as api:
            sessions = api.get_sessions()
            rdp_sessions = [
                s for s in sessions
                if s.protocol == "Rdp" and s.username == user.username
            ]
            assert len(rdp_sessions) >= CONCURRENT_CONNECTIONS, (
                f"Expected at least {CONCURRENT_CONNECTIONS} RDP sessions, "
                f"got {len(rdp_sessions)}"
            )
