import shutil
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
@pytest.mark.skip(reason="RDP TOFU not yet wired in raw-proxy mode")
class TestRdpTofu:
    def test_first_connection_pins_cert(
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
                            tls_mode="Preferred",
                        )
                    ),
                )
            )
            api.add_target_role(rdp_target.id, role.id)

        import subprocess
        import time

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
            known_hosts = api.get_rdp_known_hosts(rdp_target.id)
            assert len(known_hosts) > 0
            kh = known_hosts[0]
            assert kh.host == "localhost"
            assert kh.port == rdp_port


class TestRdpKnownHostCrud:
    def test_known_host_crud(
        self,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            rdp_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRDPOptions(
                            kind="Rdp",
                            host="localhost",
                            port=3389,
                            username="testuser",
                            password="testpass",
                            tls_mode="Preferred",
                        )
                    ),
                )
            )
            target_id = rdp_target.id

            # GET list — initially empty
            known_hosts = api.get_rdp_known_hosts(target_id)
            assert len(known_hosts) == 0

            # POST to add a cert
            test_sha256 = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
            api.add_rdp_known_host(
                target_id,
                sdk.AddRdpKnownHostRequest(
                    host="192.168.1.100",
                    port=3389,
                    certificate_sha256=test_sha256,
                ),
            )

            # GET list — should have 1 entry
            known_hosts = api.get_rdp_known_hosts(target_id)
            assert len(known_hosts) == 1
            assert known_hosts[0].certificate_sha256 == test_sha256
            assert known_hosts[0].host == "192.168.1.100"
            assert known_hosts[0].port == 3389

            # GET single by sha256
            kh = api.get_rdp_known_host(target_id, test_sha256)
            assert kh.certificate_sha256 == test_sha256
            assert kh.host == "192.168.1.100"
            assert kh.port == 3389

            # POST same cert again — expect 409 conflict
            with pytest.raises(sdk.ApiException) as exc_info:
                api.add_rdp_known_host(
                    target_id,
                    sdk.AddRdpKnownHostRequest(
                        host="192.168.1.100",
                        port=3389,
                        certificate_sha256=test_sha256,
                    ),
                )
            assert exc_info.value.status == 409

            # DELETE by sha256
            api.delete_rdp_known_host(target_id, test_sha256)

            # GET list — empty again
            known_hosts = api.get_rdp_known_hosts(target_id)
            assert len(known_hosts) == 0

            # Cleanup
            api.delete_target(target_id)

    def test_delete_target_cascades_known_hosts(
        self,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            rdp_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRDPOptions(
                            kind="Rdp",
                            host="localhost",
                            port=3389,
                            username="testuser",
                            password="testpass",
                            tls_mode="Preferred",
                        )
                    ),
                )
            )
            target_id = rdp_target.id

            # Add a known host
            test_sha256 = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
            api.add_rdp_known_host(
                target_id,
                sdk.AddRdpKnownHostRequest(
                    host="10.0.0.1",
                    port=3389,
                    certificate_sha256=test_sha256,
                ),
            )

            # Verify it exists
            known_hosts = api.get_rdp_known_hosts(target_id)
            assert len(known_hosts) == 1

            # Delete the target
            api.delete_target(target_id)

            # Verify known hosts are gone — fetching for a deleted target
            # should return 404 or an empty list
            with pytest.raises(sdk.ApiException) as exc_info:
                api.get_rdp_known_hosts(target_id)
            assert exc_info.value.status == 404
