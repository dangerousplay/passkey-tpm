"""D03: users without a fingerprint: PIN for UV, a notification click for presence (AD-022)."""
from spinagram import Activity

act = Activity(
    "D03",
    "No fingerprint: PIN + Allow",
    subtitle="The PIN proves who you are (TPM PIN gate); clicking Allow proves you are there",
    direction="down",
    layout={"engine": "layered", "direction": "down", "rank_gap": 32},
    category="flows",
)

with act.lane("Browser"):
    start = act.start()
    pin = act.action("PIN → token")
    request = act.send("makeCredential")
    done = act.receive("Passkey created")
with act.lane("Agent + you"):
    ask = act.receive("Allow / Deny?")
    click = act.decision("Allow?")
with act.lane("Broker"):
    verify = act.action("Token OK, ask caller")
    denied = act.action("OPERATION_DENIED")
with act.lane("TPM"):
    sign = act.action("Sign via UV gate")

start >> pin >> request >> verify >> ask >> click
click.yes(sign) >> done
click.no(denied)

diagram = act
