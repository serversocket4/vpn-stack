"""python -m admin run | polkit-rule"""

from __future__ import annotations

import asyncio
import logging
import sys

from admin.config import Settings

POLKIT_RULE = """// admin may only start a VPN panel job; what the job does is decided by root (vpnjob, digest)
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "bvpn-admin"
        && action.lookup("verb") == "start"
        && /^bvpn-job@[a-z0-9-]{3,40}\\.service$/.test(action.lookup("unit"))) {
        return polkit.Result.YES;
    }
});
"""


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cmd = argv[0] if argv else "run"
    if cmd == "polkit-rule":
        print(POLKIT_RULE, end="")
        return 0
    if cmd == "run":
        from admin.app import App
        asyncio.run(App(Settings()).run())
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
