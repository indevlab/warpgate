import shutil
import subprocess
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


@pytest.mark.skip(reason="RDP ticket auth not yet supported in raw-proxy mode")
@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
class Test:
    def test_auth_with_valid_ticket(
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

            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=rdp_target.name,
                    username=user.username,
                )
            ).secret

        # First connection with valid ticket should succeed
        result = subprocess.run(
            [
                "xfreerdp",
                f"/v:localhost:{shared_wg.rdp_port}",
                f"/u:{user.username}#{rdp_target.name}",
                f"/p:{secret}",
                "/cert:ignore",
                "+auth-only",
            ],
            capture_output=True,
            timeout=timeout,
        )
        assert result.returncode == 0

        # Second connection with the same ticket should fail (ticket consumed)
        result = subprocess.run(
            [
                "xfreerdp",
                f"/v:localhost:{shared_wg.rdp_port}",
                f"/u:{user.username}#{rdp_target.name}",
                f"/p:{secret}",
                "/cert:ignore",
                "+auth-only",
            ],
            capture_output=True,
            timeout=timeout,
        )
        assert result.returncode != 0

    def test_auth_with_invalid_ticket(
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

        fake_ticket = str(uuid4())
        result = subprocess.run(
            [
                "xfreerdp",
                f"/v:localhost:{shared_wg.rdp_port}",
                f"/u:{user.username}#{rdp_target.name}",
                f"/p:{fake_ticket}",
                "/cert:ignore",
                "+auth-only",
            ],
            capture_output=True,
            timeout=timeout,
        )
        assert result.returncode != 0
