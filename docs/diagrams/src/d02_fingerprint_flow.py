"""D02: registering a passkey with a fingerprint."""
from spinagram import Activity

act = Activity(
    "D02",
    "Register with a fingerprint",
    subtitle="The TPM signs only after fprintd matches the calling user's finger at the seat",
    direction="down",
    layout={"engine": "layered", "direction": "down", "rank_gap": 36},
    category="flows",
)

with act.lane("Browser"):
    start = act.start()
    request = act.send("makeCredential")
    done = act.receive("Passkey created")
    finish = act.end()
with act.lane("Agent (your session)"):
    relay = act.action("Relay via D-Bus")
    prompt = act.action("Touch prompt")
with act.lane("Broker"):
    check = act.action("Seat + request check")
    match = act.decision("Match?")
    denied = act.action("OPERATION_DENIED")
with act.lane("fprintd"):
    scan = act.action("Verify finger")
with act.lane("TPM"):
    sign = act.action("Sign via UV gate")

start >> request >> relay >> check >> scan >> match
relay >> prompt
match.yes(sign) >> done >> finish
match.no(denied)

diagram = act
