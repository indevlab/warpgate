import shutil
import subprocess
import time
from base64 import b64decode
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
@pytest.mark.skip(reason="RDP MFA not yet supported in raw-proxy mode")
class Test:
    def test_auth_with_totp_required(
        self,
        processes: ProcessManager,
        otp_key_base64: str,
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
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(
                    secret_key=list(b64decode(otp_key_base64)),
                ),
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        rdp=["Password", "Totp"],
                    ),
                ),
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
        assert result.returncode != 0

    def test_auth_with_totp_not_required(
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

        time.sleep(1)

        with admin_client(url) as api:
            sessions = api.get_sessions()
            rdp_sessions = [
                s for s in sessions
                if s.protocol == "Rdp" and s.username == user.username
            ]
            assert len(rdp_sessions) > 0
