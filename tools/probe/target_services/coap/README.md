# Controlled CoAP responder

The CoAP probe plugin generates this target service from the selected,
materialized probe plans. It runs only on a disposable provider target; it is
not a developer-host service.

The responder binds the target endpoint's IPv4 address on UDP port 5683 and
matches each request by exact datagram bytes. It emits only the planned response
sequence for the seven admitted UDP cases: piggybacked Content, Empty ACK plus
separate Content, Reset, one Observe notification, one Block1 exchange, one
Block2 exchange, and Echo/Request-Tag correlation. Reliable CoAP, Q-Block
scheduling, malformed candidates, and OSCORE contexts remain offline-only.

Execution is bounded to at most ten received requests and sixty seconds. Setup
records the generated responder, PID, stdout/stderr, and JSONL exchange log
under the provider artifact root, and appends PID termination to the normal
target cleanup script.

Live use requires all of the probe runner's provider and
`--confirm-live-run` gates plus `LIBCRAFTER_COAP_LIVE_CONFIRM=yes`. Dry-runs
render the service contract and setup metadata without provisioning endpoints,
binding sockets, or sending packets.
