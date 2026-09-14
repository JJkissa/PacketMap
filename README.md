# PacketMap

PacketMap turns a packet capture into a local, readable view of who talked to whom.
Load a `.pcap` or `.pcapng` file, then explore endpoint relationships, protocols,
traffic volume, DNS names, approximate geography, and capture timelines in your
browser.

Everything runs on your computer. PacketMap binds to loopback, uses bundled data,
and does not send captures to a cloud service.

## What you can do

- Draw a topology of endpoints and their observed connections.
- Browse every scoped node on an offline geographic map.
- Filter by IP address, DNS name, observed MAC address, protocol, or service hint.
- Inspect packets, bytes, peers, ports, timestamps, DNS names, and MAC observations.
- View protocol and time charts, including sparse timelines with zero-traffic gaps.
- Export aggregated capture data as JSON.
- Optionally send redacted, aggregated node summaries to a local LM Studio model.
- Look up MAC vendors locally after installing the optional allocation database.

PacketMap is an analysis aid, not a replacement for Wireshark or a complete network
inventory. Read the interpretation limits before treating a result as evidence.

## Quick start

### From the Desktop

Double-click the PacketMap launcher. If Linux asks whether to trust the launcher,
choose `Allow Launching` or `Trust and Launch`.

A terminal starts the local server and opens the browser. Keep that terminal open
while using the app. Press `Ctrl+C` in it to stop the server. Closing the browser
tab does not stop the server.

### From a terminal

From the project directory:

```text
./run.sh
```

PacketMap normally opens at:

```text
http://127.0.0.1:8765
```

If the browser does not open, visit that address yourself. If the port is already
occupied, let PacketMap choose a free port:

```text
./run.sh --port 0
```

To start the server without opening a browser:

```text
./run.sh --no-browser
```

The selected capture can be a file saved by Wireshark. Wireshark does not need to
be installed on the machine doing the analysis, and PacketMap does not require
administrator or root privileges.

## Exploring a capture

The Topology view draws endpoints as nodes and observed connections as lines.
Thicker lines represent more captured bytes. Both directions are combined, so a
line does not prove which endpoint initiated a session.

The graph intentionally shows a readable subset. Use its shown/total count and the
Connections table when you need the complete scoped list.

The Geography view accounts for every node in the current scope, unlike the
limited topology drawing. Nearby endpoints may be grouped into counted markers;
select a marker to list its endpoints. Private, reserved, multicast, invalid, and
unmapped addresses remain visible in the paginated list, but PacketMap does not
invent map positions for them.

- Drag or use the arrow keys to pan.
- Use the zoom controls to change scale.
- Use World to reset the view.

Search and protocol/service filters apply to both views. The analysis scope can be
`All filtered nodes` or `Selected node only`. To use the latter, select an endpoint
first and then choose the scope. If the selected endpoint is outside the current
filter, the scope is empty rather than silently falling back to all nodes. Search
also includes direct peers, as described above the filters.

### Service filters

The service menu includes RDP, SSH, Telnet, HTTP, HTTPS, DNS, FTP, SMTP, IMAP,
POP3, SMB, NTP, SNMP, LDAP, DHCP, and mDNS. Each option shows the transport and
ports it matches. For example, RDP includes TCP/UDP 3389 and HTTPS includes
TCP/UDP 443, which is also a QUIC/HTTP3 port hint.

These are port-based hints, not verified application detection. Nonstandard ports
can be missed, and unrelated traffic on a standard port can match. FTP matches its
control port, not dynamically negotiated data connections. Service filters count
only matching port-pair traffic in the table and edge weights; node details and
the capture summary remain whole-capture data.

Network and transport filters select whole connections. Service detail is bounded
to 64 groups per connection and 100,000 groups overall. PacketMap warns when data
is omitted and marks affected filtered totals as lower bounds. Reload older captures
to obtain the current service breakdown.

### Timeline and exports

The timeline shows captured bytes per interval. It does not estimate bandwidth.
Empty intervals are drawn at zero, but a gap in the capture is not proof that the
network was idle outside the file.

The sparse timeline stores only occupied buckets. Each bucket covers
`[time, time + timeline_bucket_width)`. The width starts at one second and doubles
as needed to keep at most 2,000 occupied buckets. Large timestamp gaps do not
create thousands of empty buckets. The chart uses at most 8,000 path vertices and
2,000 markers.

Capture JSON exports the aggregated analysis, not the original packets. It remains
whole-capture data even when the interface is filtered. Exported addresses and DNS
names may be sensitive; share them carefully.

## Offline geography

IP lookups use `data/city.mmdb` locally. PacketMap does not send captured addresses
to an external lookup API. The basemap in `static/world.json` is bundled Natural
Earth public-domain data. There are no remote map tiles, map SDKs, CDN scripts, or
geocoding calls.

Locations are approximate network allocations. They are not exact device
positions, device identity, physical traffic routes, compromise evidence, or proof
of country ownership. The synthetic demo uses documentation ranges and therefore
has no GeoIP locations. A real capture with public IP addresses may show located
endpoints.

The UI displays DB-IP City Lite attribution and the database build date. A licensed
GeoLite2-City MMDB can replace `data/city.mmdb`; PacketMap detects its provider and
updates the attribution. Unknown or custom MMDB formats are unsupported.

The repository supplied with the project, <https://github.com/wp-statistics/geo>,
lists compatible DB-IP and MaxMind city databases. The installed DB-IP database was
obtained from DB-IP's original distribution. Keep the required attribution when
sharing the application or its data. The saved SHA-256 is provenance, not a
publisher-signature verification.

Database installation is explicit and never runs when a capture is opened:

```text
.venv/bin/python scripts/install_geoip.py YYYY-MM
```

For example:

```text
.venv/bin/python scripts/install_geoip.py 2026-09
```

The installer bounds compressed and expanded sizes, validates MMDB metadata, and
atomically replaces the database. It records the source, local SHA-256, and
metadata in `data/city-source.json`. No automatic update task is installed.

## Optional local model analysis

PacketMap works without a model. To enable analysis, start LM Studio's loopback
server at `http://127.0.0.1:1234` with the model
`qwen3.8-9b-heretic-uncensored-i1`, then choose a capture, filters, and scope in
PacketMap and click `Analyze scoped nodes`.

No inference runs until you click the analysis button. With `All filtered nodes`,
PacketMap sends one sequential request per node, not one request for only the top
20 connections or the visible graph. Narrow a large scope first if needed.

Each request contains calculated aggregates from all retained matching connections:
peers, packets, bytes, the observed time window, average packet size, and the
sample's share of bytes. The detail sample includes up to eight strongest
connections, with omissions stated explicitly. Nodes without retained evidence are
counted and labeled instead of receiving invented results. Non-service protocol
filters retain whole-pair totals.

Responses separate observations, cited interpretations with confidence,
uncertainties, and concrete follow-up checks. Citations use:

- `N1` for node aggregates
- `E` IDs for sampled connections
- `G` IDs for approximate local GeoIP records

Expand Evidence to inspect the underlying values and browser-side host aliases.
Citation and schema validation do not prove that model prose is true. The model can
still misread flags or overstate a port hint.

Before submission, addresses become `Host1` and `Host2`. PacketMap does not submit
filenames, captured DNS names, MAC addresses, search text, or packet payloads.
Approximate GeoIP city/country data and traffic metadata are submitted to the
configured model, so review that model service's logging if the metadata is
sensitive.

Model settings support LM Studio native and OpenAI-compatible APIs. The URL, model,
and optional API key are editable in the interface. Keys are stored server-side at
`~/.config/packetmap/model.json` with mode `0600` and are never returned to the
browser. Changing the server URL clears a saved key unless a new key is entered.
Non-loopback endpoints require HTTPS and explicit authorization. Redirects and
proxy inheritance are disabled. Saving settings does not run inference, and
requests are limited to 2,400 tokens. PacketMap never executes model-generated
commands.

Analysis progress reports completed and total nodes. Stop preserves finished
results and halts remaining work, although an active LM Studio generation may
finish. Changing the capture, search, protocol, node, or scope discards stale
results. Only one request at a time is accepted by the local server. Network
requests time out after 150 seconds; the GUI stops waiting after 170 seconds.
Errors stop the batch and label unfinished nodes. Exported analysis includes all
completed results, scope, completion counts, and incomplete status. Results are not
persisted across reloads.

## Offline MAC vendor attribution

Install or update the optional local allocation database explicitly:

```text
python3 scripts/install_mac_vendors.py
```

PacketMap makes no per-MAC network requests. The downloaded CSV and provenance file
remain gitignored because bulk redistribution rights have not been confirmed.
Lookup uses the longest-prefix MA-L, MA-M, and MA-S/IAB records. Locally
administered, multicast, broadcast, and malformed addresses do not receive a
reliable vendor.

A vendor or device-category hint describes only the MAC observed at the capture
point. For a remote IP, that MAC is commonly a gateway or next hop. See
[`MAC_VENDOR.md`](MAC_VENDOR.md) for provenance, matching rules, and interpretation
limits.

## Privacy and safety

PacketMap is a local personal tool, not a hardened multi-user web service.

- The server listens only on `127.0.0.1`.
- Captures are uploaded to a randomly located temporary file for decoding.
- The temporary file is deleted after the request, including handled failures.
- The original capture is never modified.
- Normal analysis works offline with no telemetry, cloud service, CDN, or remote
  scripts.
- Do not change the bind address to expose PacketMap to a network.
- Treat exported addresses and names as sensitive.

When using Snap Firefox, a root-owned capture can be blocked by the browser sandbox
even if its permissions look readable. Save a new copy as your normal user in your
home directory instead. Do not run the browser as root or disable its sandbox.

## Limits and interpretation

- Uploads are limited to 256 MiB. Split larger files with Wireshark or `editcap`.
- Analysis is capped at 500,000 packets, 20,000 endpoints, and 50,000 connections.
  Warnings identify partial results.
- The topology graph is a readable subset, not a network inventory.
- Common IPv4, IPv6, TCP, UDP, ICMP, ARP, and DNS traffic are supported. Unusual or
  damaged captures may decode only partially; PacketMap does not claim full
  Wireshark dissector parity.
- TLS/HTTPS, VPN, and encrypted DNS payloads are not decrypted.
- Ports suggest services but do not prove which application ran.
- PacketMap does not perform general TCP-stream reassembly, IP-fragment reassembly,
  malware verdicts, passive OS detection, live capture, or device discovery.
- Capture placement, packet loss, truncation, and capture filters affect the result.
  Only traffic present in the file can be represented.
- Byte counts describe captured traffic metadata, not application payload size or
  bandwidth measured on every network link.
- Demo captures are artificial and are not captures of your LAN.

### DNS and MAC interpretation

DNS labels come from decoded DNS answers in the capture. PacketMap does not contact
DNS servers, geolocation services, or vendor lookup services. Missing names may
mean the answers were not captured, were cached, or were encrypted. A DNS name is
a clue, not proof of device identity, and one address can have several names.

MAC addresses are observations at the capture point. Across a router, Ethernet
usually shows the router's MAC rather than the remote server's MAC. Several IPs can
therefore share an observed MAC. PacketMap does not automatically merge those IP
nodes into one physical device.

## Installing on another Linux computer

Copy the source folder, but recreate `.venv`; virtual environments are not
portable. You need Python 3.10 or newer and a modern browser. Initial dependency
installation requires internet access. Later analysis can run offline.

Using `uv`:

```text
cd /path/to/PacketMap
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
chmod +x run.sh
./run.sh
```

Using standard Python:

```text
cd /path/to/PacketMap
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
chmod +x run.sh
./run.sh
```

For development, also install `pytest`. Node.js is needed for frontend unit tests;
Playwright is needed only for browser automation, not normal use.

If you move the project, update the Desktop launcher's `Exec` and `Path` entries.

## Development

PacketMap starts with `run.sh`, which launches `app.py` using the local Python
environment. `app.py` serves the interface on loopback. The browser uploads the
selected file, `analyzer.py` uses Scapy to aggregate endpoint pairs, protocol
counts, byte totals, timestamps, and DNS names, and the server removes the
temporary upload after processing.

Run the test suite from the project directory:

```text
.venv/bin/python -m pytest -q
node --test tests/test_frontend.cjs
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_timeline_browser.py
.venv/bin/python examples/make_demo.py
```

Developer verification for the model path is opt-in:

```text
PACKETMAP_TEST_LLM=1 .venv/bin/python -m pytest tests/test_llm.py tests/test_llm_browser.py -q
.venv/bin/python -m pytest tests -q
node --test tests/*.cjs
```

Use tests first when adding behavior: create a small artificial capture, make the
test fail, implement the change, and run the full suite. Do not commit private
production captures as fixtures. Treat packet text as untrusted and render it as
text, never HTML. Keep limits visible and do not hide discarded data behind
apparently complete totals.

The parser's node lookup examines the packet's at most two unique endpoints rather
than every accumulated node. Metadata is built and classified only when missing.
Output ordering, counts, warnings, and cap semantics remain unchanged.

For a reproducible synthetic benchmark, run three times per size with a new output
path each time:

```text
.venv/bin/python tests/test_node_lookup.py /tmp/packetmap-benchmark.json
```

Reports include complete outputs and node/edge cap boundary cases for exact
before/after comparison. Captures are temporary, no network lookups are used, and
timing is informational rather than a test threshold.

### Project layout

```text
app.py                  Loopback HTTP server, upload safety, app entry
analyzer.py             Packet parsing and aggregation; analyze(path)
static/index.html       Page structure and accessible controls
static/style.css        Colors, spacing, responsive layout
static/app.js           Map, filters, detail panel, and charts
examples/make_demo.py   Regenerate artificial demo captures
tests/                  Parser, server, integration, and frontend tests
requirements.txt        Pinned runtime dependencies
run.sh                  Linux launcher
```

The example captures are `examples/demo.pcap` and `examples/demo.pcapng`.
`README.md` is the canonical project guide. `README.txt` is an identical visible
copy for local file managers.

## Possible next steps

Ideas that have not been implemented yet include applying time ranges to topology
analysis, a separate MAC-layer map, conversation direction and handshake
analysis, DNS CNAME/TTL history, a background parser process with cancellation,
and an AppImage package.
