import json
import shutil
import subprocess
import time
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


@pytest.mark.skipif(
    shutil.which("xfreerdp") is None, reason="xfreerdp not installed"
)
class Test:
    def test_rdp_session_recording(
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

        # Connect without +auth-only so an actual session is established
        # and recording data is produced. Use a short timeout to disconnect
        # after a few seconds of session activity.
        try:
            subprocess.run(
                [
                    "xfreerdp",
                    f"/v:localhost:{shared_wg.rdp_port}",
                    f"/u:{user.username}#{rdp_target.name}",
                    "/p:123",
                    "/cert:ignore",
                ],
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            # Expected — we intentionally let the connection time out
            pass

        # Give the server time to flush recording data
        time.sleep(3)

        with admin_client(url) as api:
            sessions = api.get_sessions()
            rdp_sessions = [
                s for s in sessions
                if s.protocol == "Rdp" and s.username == user.username
            ]
            assert len(rdp_sessions) > 0, "No RDP sessions found"

            session = rdp_sessions[0]
            recordings = api.get_session_recordings(session.id)
            assert len(recordings) > 0, "No recordings found for the RDP session"

            recording = recordings[0]
            assert recording.kind == "Rdp"

        # Fetch the raw RDP recording via the dedicated endpoint
        recording_url = (
            f"{url}/@warpgate/admin/api/recordings/{recording.id}/rdp"
        )
        resp = requests.get(
            recording_url,
            auth=("admin", "admin"),
            verify=False,
        )
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/x-ndjson"

        # Parse and verify the NDJSON content
        lines = [
            line for line in resp.text.strip().split("\n") if line.strip()
        ]
        assert len(lines) >= 1, "Recording NDJSON is empty"

        header = json.loads(lines[0])
        assert header["type"] == "header"
        assert header["version"] == 1

        screenshot_frames = [
            json.loads(line) for line in lines[1:]
            if json.loads(line).get("type") == "screenshot"
        ]
        assert len(screenshot_frames) > 0, (
            "No screenshot frames found in RDP recording"
        )
