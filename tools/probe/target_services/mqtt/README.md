# MQTT Probe Broker Provisioning

`provision-broker.sh` is run by probe-owned target-service setup on a
disposable lab endpoint to install Mosquitto and configure an MQTT broker for
`crafter` MQTT behavior checks. It is intentionally not run from the repository
host.

The broker listens on TCP port `1883`, binds to the endpoint lab IPv4 address,
and enables anonymous access because each run uses a disposable test endpoint.
The config disables persistence so broker state does not survive provider
cleanup.

Defaults use documentation addresses:

- `MQTT_BIND_IPV4=192.0.2.20`
- `MQTT_PORT=1883`
- `MOSQUITTO_CONF=/etc/mosquitto/mosquitto.conf`
- `MOSQUITTO_TEMPLATE=tools/probe/target_services/mqtt/mosquitto.conf.template`

Example lab-endpoint use:

```sh
MQTT_BIND_IPV4=192.0.2.20 ./provision-broker.sh
```

Do not commit endpoint-specific hostnames, public IPs, provider IDs,
credentials, or live packet captures from lab runs.
