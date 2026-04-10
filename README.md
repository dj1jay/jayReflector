# jayReflector

**jayReflector** is a fork of [GeuReflector](https://github.com/iw1geu/GeuReflector) by IW1GEU,
extended by DJ1JAY / FM-Funknetz with MQTT node exchange, TG mapping, satellite TG filtering and more.

The wire protocol is **100% backward compatible** with GeuReflector v3.
Unknown message types are silently ignored by older peers — mixed deployments work.

---

## Features over GeuReflector

| Feature | Description |
|---------|-------------|
| **MQTT Node Exchange** | Each reflector publishes connected nodes, talkers and satellite info to MQTT via a standalone daemon |
| **TCP Node List** | Connected client lists are exchanged between trunk peers on login/logout/TG change |
| **Location Data** | LAT/LON/QTH name from node info is included in node lists |
| **TG Mapping** | Bidirectional TG remapping per trunk link (e.g. peer TG 1 ↔ local TG 2624123) |
| **ALLOW_TGS Whitelist** | Per-link exact TG whitelist with flexible syntax |
| **Flexible Filter Syntax** | Exact (`26200`), prefix (`24*`), range (`2427-2438`) for all filter fields |
| **Satellite TG Filter** | Satellites declare which TGs they want — bidirectional, reduces bandwidth |
| **PTY Hot-Reload** | `TRUNK_RELOAD` reloads BLACKLIST_TGS, ALLOW_TGS, TG_MAP without restart |
| **Mute via PTY** | `TRUNK_MUTE` / `TRUNK_UNMUTE` per callsign per trunk link |
| **Debounce Timer** | Node list sends are debounced (500ms) to avoid spam on mass login |
| **MQTT Daemon** | Separate `jay-mqtt-daemon.py` handles MQTT — reflector never blocks on network I/O |

---

## Build

```bash
# Clone
git clone https://github.com/DJ1JAY/jayReflector.git
cd jayReflector

# Build
cmake -S src -B build -DLOCAL_STATE_DIR=/var -DUSE_QT=OFF
cmake --build build --target svxreflector

# Binary
build/bin/svxreflector
```

**Dependencies:**
```bash
apt install build-essential cmake libsigc++-2.0-dev libssl-dev \
            libjsoncpp-dev libpopt-dev mosquitto-clients python3-pip
pip3 install paho-mqtt
```

---

## MQTT Daemon

The reflector sends MQTT data via Unix socket to `jay-mqtt-daemon.py`.
This avoids blocking the event loop on network I/O.

```bash
# Install
cp jay-mqtt-daemon.py /usr/local/bin/
chmod +x /usr/local/bin/jay-mqtt-daemon.py

# Configure systemd service
cp jay-mqtt-daemon.service /etc/systemd/system/
# Edit: replace MQTT_HOST with your broker address
nano /etc/systemd/system/jay-mqtt-daemon.service

systemctl daemon-reload
systemctl enable --now jay-mqtt-daemon

# Create socket directory
mkdir -p /var/run/svxreflector
```

---

## Configuration

### `[GLOBAL]`

```ini
[GLOBAL]
LISTEN_PORT=5300
HTTP_SRV_PORT=8080
COMMAND_PTY=/dev/shm/svxreflector_ctrl

# Trunk
TRUNK_LISTEN_PORT=5302
TRUNK_DEBUG=0

# MQTT (published via jay-mqtt-daemon)
TRUNK_MQTT_TOPIC=svxreflector/trunk/mynetwork/nc1
TRUNK_MQTT_TALKER=1
TRUNK_MQTT_SOCKET=/var/run/svxreflector/mqtt.sock

# TGs forwarded to ALL peers simultaneously
CLUSTER_TGS=26262,26298
```

### `[TRUNK_xyz]` — per trunk link

```ini
[TRUNK_PARTNER1]
HOST=partner1.example.org
PORT=5302
SECRET=SharedSecret123
REMOTE_PREFIX=1,2,3,4,5,6,7,8,9
MQTT_NAME=Master-NC1

# Optional filters (flexible syntax: exact, prefix*, range-)
BLACKLIST_TGS=9,99,9998,9999
ALLOW_TGS=24*,26200,2427-2438

# Bidirectional TG mapping: peer_tg:local_tg
TG_MAP=1:2624100,2:2624101
```

### Satellite (parent side)

```ini
[GLOBAL]
SATELLITE_LISTEN_PORT=5303
SATELLITE_SECRET=SatSecret123
```

### Satellite (client side)

```ini
[GLOBAL]
SATELLITE_OF=parent.example.org:5303
SATELLITE_ID=my-satellite
SATELLITE_SECRET=SatSecret123

# Bidirectional TG filter — only these TGs go in and out via trunk
# Flexible syntax: exact, prefix*, range-
SATELLITE_FILTER=26200,262*,2427-2438
```

---

## Filter Syntax

Used in `BLACKLIST_TGS`, `ALLOW_TGS` and `SATELLITE_FILTER`:

| Syntax | Example | Matches |
|--------|---------|---------|
| Exact | `26200` | Only TG 26200 |
| Prefix | `24*` | TG 24, 240, 2400, 24000, ... |
| Range | `2427-2438` | TG 2427 to 2438 inclusive |
| Combined | `24*,26200,2427-2438` | All of the above |

---

## PTY Commands

Configure `COMMAND_PTY=/dev/shm/svxreflector_ctrl` in `[GLOBAL]`.

```bash
# Show status of all trunk links
echo "TRUNK_STATUS" > /dev/shm/svxreflector_ctrl

# Mute/unmute a callsign on a specific link
echo "TRUNK_MUTE TRUNK_PARTNER1 DB0ABC" > /dev/shm/svxreflector_ctrl
echo "TRUNK_UNMUTE TRUNK_PARTNER1 DB0ABC" > /dev/shm/svxreflector_ctrl

# Hot-reload BLACKLIST_TGS, ALLOW_TGS, TG_MAP (no restart needed)
echo "TRUNK_RELOAD" > /dev/shm/svxreflector_ctrl
echo "TRUNK_RELOAD TRUNK_PARTNER1" > /dev/shm/svxreflector_ctrl
```

---

## MQTT Topics

All topics are published under `TRUNK_MQTT_TOPIC` (e.g. `svxreflector/trunk/mynetwork/nc1`).

```
<TOPIC>/<MQTT_NAME>/<SECTION>              Trunk link status + active talkers
<TOPIC>/<MQTT_NAME>/nodes/local            Locally connected nodes + TG + location
<TOPIC>/<MQTT_NAME>/nodes/<PEER_ID>        Nodes received from trunk peer via TCP
<TOPIC>/<MQTT_NAME>/talker                 Active local talker (if TRUNK_MQTT_TALKER=1)
<TOPIC>/satellite/<satellite_id>/status    Satellite connection status
<TOPIC>/satellite/<satellite_id>/talker    Active talker on satellite
<TOPIC>/satellite/<satellite_id>/nodes     Nodes connected to satellite
```

**Node list payload example:**
```json
{
  "nodes": [
    {"callsign": "DB0RUF", "tg": 26298, "lat": 50.627, "lon": 10.474, "qth_name": "Dolmar"},
    {"callsign": "DJ1JAY", "tg": 0}
  ],
  "timestamp": 1744123456
}
```

---

## TG Mapping Example

NRW network uses TG 1 internally, FM-Funknetz uses TG 2624100:

**FM-Funknetz side:**
```ini
[TRUNK_NRW]
HOST=nrw.example.org
PORT=5302
SECRET=SharedSecret
REMOTE_PREFIX=1,2,3
ALLOW_TGS=1,2
TG_MAP=1:2624100,2:2624101
MQTT_NAME=Master-NC1
```

Result:
- NRW speaks on TG 1 → FM hears on TG 2624100
- FM speaks on TG 2624100 → NRW hears on TG 1
- No config change needed on NRW side

---

## Satellite TG Filter Example

A satellite that only needs TGs 26200 and the 262x range:

```ini
SATELLITE_FILTER=26200,262*
```

- Satellite only **receives** audio for TG 26200 and 262x from parent
- Satellite only **sends** audio for TG 26200 and 262x to parent
- All other TGs remain local — no ghost talkers

---

## Credits

- **SM0SVX** — Original SvxReflector
- **IW1GEU** — GeuReflector trunk/satellite implementation
- **DJ1JAY / FM-Funknetz** — MQTT node exchange, TG mapping, flexible filters, satellite filter, hot-reload and more

---

## License

GNU GPL v2 or later — see original SvxLink license.
