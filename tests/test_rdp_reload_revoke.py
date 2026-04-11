import shutil
import subprocess
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
class Test:
    def test_revoke_role_blocks_new_connections(
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

        result = subprocess.run(
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
        assert result.returncode == 0

        with admin_client(url) as api:
            api.delete_target_role(id=rdp_target.id, role_id=role.id)

        time.sleep(2)

        result = subprocess.run(
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
        assert result.returncode != 0
