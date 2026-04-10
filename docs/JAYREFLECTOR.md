# jayReflector Feature Reference

## Config Keys

### `[TRUNK_x]` section

| Key | Default | Description |
|-----|---------|-------------|
| `HOST` | — | Peer hostname/IP |
| `PORT` | 5302 | Trunk TCP port |
| `SECRET` | — | Shared secret (must match peer) |
| `REMOTE_PREFIX` | — | TG prefixes owned by peer |
| `PEER_ID` | section name | ID sent in hello, used as MQTT topic name for peer nodes |
| `MQTT_NAME` | section name | This server's name in MQTT topics |
| `BLACKLIST_TGS` | — | Comma-separated TGs never forwarded |

### `[GLOBAL]` additions

| Key | Default | Description |
|-----|---------|-------------|
| `TRUNK_MQTT_HOST` | — | MQTT broker (enables publishing) |
| `TRUNK_MQTT_PORT` | 1883 | MQTT broker port |
| `TRUNK_MQTT_TOPIC` | `svxreflector/trunk` | Topic prefix |
| `TRUNK_DEBUG` | 0 | Verbose trunk logging |

## MQTT Topic Structure

```
<TOPIC_PREFIX>/<MQTT_NAME>/<SECTION>              trunk link status
<TOPIC_PREFIX>/<MQTT_NAME>/nodes/local            local nodes
<TOPIC_PREFIX>/<MQTT_NAME>/nodes/<PEER_ID>        nodes from trunk peer
<TOPIC_PREFIX>/satellite/<satellite_id>/status    satellite status
<TOPIC_PREFIX>/satellite/<satellite_id>/talker    satellite active talker
<TOPIC_PREFIX>/satellite/<satellite_id>/nodes     satellite nodes
```

All topics are published with **retained** flag.

## PTY Commands

```bash
TRUNK_MUTE <section> <callsign>    # block audio from callsign
TRUNK_UNMUTE <section> <callsign>  # unblock
TRUNK_STATUS                       # log all trunk links
```

## Node Exchange Protocol

`MsgTrunkNodeList` (type 121) is sent peer-to-peer on:
- Client login
- Client logout
- Client TG change

The receiving server publishes it to its own MQTT. Peers without MQTT
never need to know about the broker. GeuReflector peers silently ignore
type 121 — fully backward compatible.

## Satellite Node Exchange

Satellites (running in `SATELLITE_OF` mode) also send `MsgTrunkNodeList`
to their parent. The parent publishes under:
```
<TOPIC_PREFIX>/satellite/<satellite_id>/nodes
```
