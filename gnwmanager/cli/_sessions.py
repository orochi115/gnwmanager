"""Desktop discovery and constrained machine controls; no direct QMP connection."""

import json
from typing import Annotated, Literal, Optional

from cyclopts import Parameter, validators

from gnwmanager.cli.main import app
from gnwmanager.cli.session_route import SessionRoute

_SessionRoute = Annotated[SessionRoute, Parameter(parse=False)]


@app.command(group="Admin")
def sessions(*, session_route: _SessionRoute):
    """List reachable desktop sessions without acquiring a device."""
    for found in session_route.sessions():
        item = found.session
        print(f"{item['sessionId']}  {item['model']}  {item['execution']}  {item['profileName']}")


@app.command(group="Admin")
def device_state(*, session_route: _SessionRoute):
    """Read the selected desktop device state."""
    print(json.dumps(session_route.lease().status(), sort_keys=True))


@app.command(group="Admin")
def power(
    action: Literal["pause", "resume", "warm-reset", "cold-start", "battery", "battery-present", "usb-power"],
    value: Optional[str] = None,
    *,
    session_route: _SessionRoute,
):
    """Control execution or supply through the desktop owner.

    Boolean supply values are true/false; battery values range from 0 to 100.
    """
    if action == "battery":
        if value is None:
            raise ValueError("battery requires a value from 0 to 100")
        parsed = int(value)
        if not 0 <= parsed <= 100:
            raise ValueError("battery must range from 0 to 100")
    elif action in ("battery-present", "usb-power"):
        if value not in ("true", "false"):
            raise ValueError(f"{action} requires true or false")
        parsed = value == "true"
    else:
        if value is not None:
            raise ValueError(f"{action} does not accept a value")
        parsed = None
    owner = session_route
    result = owner.lease().control(action, parsed)
    if action in ("warm-reset", "cold-start") and owner._gnw is not None:
        owner._gnw.invalidate_manager_state()
    print(json.dumps(result, sort_keys=True))


@app.command(group="Admin")
def press(
    mask: Annotated[
        int,
        Parameter(converter=lambda _t, tokens: int(tokens[0].value, 0), validator=validators.Number(gte=0, lte=4095)),
    ],
    *,
    duration_ms: Annotated[int, Parameter(validator=validators.Number(gte=1, lte=30000))] = 100,
    session_route: _SessionRoute,
):
    """Press the desktop's documented 12-bit button mask for a bounded duration."""
    print(json.dumps(session_route.lease().control("press", {"mask": mask, "durationMs": duration_ms}), sort_keys=True))
