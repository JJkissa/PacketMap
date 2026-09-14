PacketMap — see who talked to whom
=================================

QUICK START (this computer)

Double-click PacketMap on the Desktop. If Linux asks, choose “Allow
Launching” / “Trust and Launch”. A terminal starts and your browser opens.
Alternatively, open a terminal and run:

  ./run.sh

In the browser, choose a .pcap or .pcapng file saved by Wireshark, or load
the clearly labeled synthetic demo. You do not need Wireshark installed
to analyze a saved capture. No administrator/root privileges are needed.

Leave the terminal open while using the app. Press Ctrl+C in that terminal
to stop it. Closing just the browser tab does NOT stop the server.
If the browser does not open, visit http://127.0.0.1:8765 manually.
If that port is occupied, run:

  ./run.sh --port 0

Open the address printed in the terminal. For no automatic browser:

  ./run.sh --no-browser

GEOGRAPHIC MAP AND SHARED ANALYSIS SCOPE

Choose View > Geography for the offline geographic map, or Topology for the
connection diagram. Search and protocol/service filters apply to both views.
Map and analysis scope provides All filtered nodes or Selected node only.
Selection is explicit: first select an endpoint, then choose Selected node only.
A selection outside the current filter produces an empty scope, not a fallback
to all nodes. Search includes direct peers, as stated above the filters.

Geography accounts for every scoped node, unlike the top-40 topology drawing.
Approximate co-located endpoints are grouped into counted markers; click a
cluster to list its endpoints. The paginated list includes private, reserved,
multicast, invalid and unmapped addresses without inventing map positions.
Pan by dragging or using arrow keys; zoom with the buttons; World view resets.
Locations are approximate network allocations, not exact device positions,
identity, physical traffic routes, compromise evidence or country ownership.
The synthetic demo uses documentation ranges and intentionally has no GeoIP
locations. A real capture containing public IPs will show located endpoints.

All IP lookups use data/city.mmdb locally. No captured address is sent to an
external API. The basemap (static/world.json) is bundled Natural Earth public-
domain data; there are no remote tiles, map SDKs, CDN scripts or geocoding calls.
DB-IP City Lite (CC BY 4.0) attribution and database build date are visible.
The repository supplied by the user, https://github.com/wp-statistics/geo,
lists compatible DB-IP and MaxMind city MMDB databases. The installed DB-IP
2026-09 database was obtained directly from DB-IP's original distribution.
A licensed GeoLite2-City MMDB can also replace data/city.mmdb; the UI detects its
provider and changes attribution. Unknown/custom MMDB formats are unsupported.

Database installation/update is explicit, never triggered by opening a capture:
  .venv/bin/python scripts/install_geoip.py YYYY-MM
Example of the currently installed edition:
  .venv/bin/python scripts/install_geoip.py 2026-09
This downloads a public database from download.db-ip.com, bounds compressed
and expanded sizes, validates MMDB metadata, and atomically replaces the file.
Source, local SHA-256 and database metadata are saved to data/city-source.json.
The stored SHA is provenance, not a publisher-signature verification. Keep
attribution when sharing this app/data. No automatic update task was installed.

OPTIONAL LOCAL MODEL ANALYSIS

Load qwen3.8-9b-heretic-uncensored-i1 in LM Studio and start its loopback server
on 127.0.0.1:1234. Choose a capture, filters and shared scope; click Analyze
scoped nodes. No inference runs until clicked. PacketMap otherwise works with
LM Studio stopped. All filtered nodes means one sequential request per node,
not one request covering the top 20 connections or only the visible graph.
Large captures may take a long time: scope down first when appropriate.

Each node receives calculated aggregates from ALL retained connections matching
the filter: peers, packets, bytes, observed window, average packet size, and
the detailed sample's share of bytes. Up to 8 strongest connections are sent
as a detail sample; its omissions are explicit. Truncated parser data remains
partial. Nodes without retained evidence are counted and labeled, not given
invented model results. Non-service protocol filters retain whole-pair totals.

Responses separate observations, cited interpretations with confidence,
uncertainties and concrete follow-up capture/filter checks. Follow-up checks
are application-generated to prevent invented UI features from the model. N1 cites node
aggregates; E IDs cite sampled connections; G IDs cite approximate local GeoIP
records. Expand Evidence sent to inspect actual values and browser-side host
aliases. Citation/schema validation does NOT prove the model's prose is true.
The model can still misread flags or overstate a port hint; verify its claims.

Addresses become Host1/Host2 before model submission. No filenames, captured
DNS names, MACs, search text or packet payloads are submitted. Approximate GeoIP
city/country and traffic metadata ARE submitted to the configured model. Review
the model service's logging if that metadata is sensitive. Model settings default
to http://localhost:1234 and support LM Studio native or OpenAI-compatible APIs.
The URL, model and optional API key are editable in the interface. Keys are stored
server-side in ~/.config/packetmap/model.json with mode 0600 and are never returned
to the browser. Changing the server URL clears a saved key unless a new key is
entered. Non-loopback endpoints require HTTPS and explicit authorization;
redirects and proxy inheritance are disabled. Saving settings does not run inference.
Requests use a 2400-token maximum. There is no automatic command execution.

Progress states completed/total nodes. Stop preserves finished results and
halts remaining work; an active LM Studio generation may still finish. Changing
capture, search, protocol or node/scope discards stale results. One request at
a time is accepted by the local server. Network timeout is 150 seconds; the GUI
stops waiting after 170 seconds. Errors stop the batch and label unfinished
nodes. Export analysis saves all completed node results plus scope, completion
counts and incomplete status; pagination only limits displayed result cards.
Capture JSON export remains separate. Results are not persisted across reloads.

Developer verification (real model calls explicitly opt-in):
  PACKETMAP_TEST_LLM=1 .venv/bin/python -m pytest tests/test_llm.py tests/test_llm_browser.py -q
  .venv/bin/python -m pytest tests -q
  node --test tests/*.cjs

TROUBLESHOOTING CAPTURE UPLOADS

If a capture fails in Snap Firefox but works in another browser, check file
ownership as well as permissions. A root-owned capture can be blocked by the
browser sandbox even with world-readable permissions. Save a new copy as your
normal user in your home folder and select that copy. Changing read permissions
alone may not help. Do not run the browser as root or disable its sandbox.

The app reports file-read failures with recovery guidance. File reads time out
after 30 seconds, local-server configuration after 15 seconds, and upload plus
analysis/response reading after 180 seconds. Controls become available again
on failure. A timed-out HTTP request is aborted, but Python may still finish
analysis; wait before retrying, or restart the server and use a smaller capture.

Launch from this project folder with ./run.sh. Developer verification commands
are listed below.

WHAT YOU ARE LOOKING AT

The connection map shows endpoints and lines between endpoints that
exchanged packets. Thicker lines mean more captured bytes. Connections
combine both directions: a line is not proof of who initiated a session.
Search by IP address, DNS name, or observed MAC address. Use the protocol
filter to reduce clutter. Select an endpoint to inspect its names, MAC
observations, and peers. The graph intentionally limits visible endpoints;
read its shown/total count rather than assuming the map shows everything.

Use the protocol/service dropdown above the map to filter RDP, SSH, Telnet,
HTTP, HTTPS, DNS, FTP, SMTP, IMAP, POP3, SMB, NTP, SNMP, LDAP, DHCP or mDNS.
Each service option shows the exact transport/ports matched; RDP includes
TCP/UDP 3389 and HTTPS includes TCP/UDP 443 (a QUIC/HTTP3 port hint).
Observed TCP, UDP, ARP and other network protocols remain in a separate group.

These filters select endpoint-pair connections using either endpoint's observed
ports. They are conventional port hints, not verified application detection:
nonstandard ports and ports omitted by the 64-port-per-edge metadata limit may
be missed, and unrelated traffic on standard ports may match. FTP matches its
control port, not dynamically negotiated data connections. Search combines
with the selected filter; Reset view clears both. For service filters, table
packet/byte totals and map-edge weights now count only matching port-pair
traffic. Node sizes/details and the capture summary remain whole-capture data.
The protocol chart follows the active search, service/protocol and analysis scope;
the timeline has an explicit adjustable display range. Exported capture JSON remains
whole-capture data. Network/transport filters still select whole connections.
Service detail is bounded to 64 groups per connection / 100,000 overall;
omitted detail is warned and affected filtered totals are marked as lower bounds.
Reload captures loaded by an older server to obtain the new breakdown.

Protocol and time charts give a quick traffic overview. The connections
table helps when a picture is less precise than a list. Export JSON saves
the aggregated analysis, not the original packets. Exported addresses and
DNS names can still be sensitive; share them carefully.

The timeline shows bytes per interval, not interpolated bandwidth. Unoccupied
intervals are drawn at zero captured traffic; this is not proof a network was
idle outside this capture. Labels and tooltips state seconds per interval.
JSON adds timeline_bucket_width (seconds); existing aggregate fields and
totals are unchanged. The sparse timeline contains only occupied buckets,
each covering [time, time + timeline_bucket_width). Missing intervals are zero.
Width starts at 1 second and doubles as needed to retain at most 2,000 occupied
buckets. Coarser buckets cannot reveal idle periods inside an interval.
Huge timestamp gaps do not allocate empty buckets: the chart uses four
vertices per occupied bucket (at most 8,000 per path) and at most 2,000 markers.

DNS labels are names present in decoded DNS answers in this capture. The
app does NOT contact DNS servers, geolocation services, or vendor lookup
services. Missing names usually mean the relevant answers were not
captured, were cached, or were encrypted. A DNS name is a clue, not proof
of a device's identity. An address can have several names.

IMPORTANT: MAC addresses are observations at the capture point, not proof
of remote ownership. When you contact a server across a router, Ethernet
usually shows the router's MAC, NOT the remote server's MAC. Several IPs
can therefore share an observed MAC. This is expected. IP nodes with MAC
observations are not automatically merged into one physical device.


OFFLINE MAC VENDOR ATTRIBUTION

Install or update the optional local allocation database explicitly:
  python3 scripts/install_mac_vendors.py

PacketMap performs no per-MAC network requests. The downloaded CSV and provenance
file stay gitignored because bulk redistribution rights were not confirmed. Lookup
uses longest-prefix MA-L, MA-M and MA-S/IAB records. Locally administered,
multicast, broadcast and malformed addresses never receive a reliable vendor.
Vendor allocation and low-confidence device-category hints describe only the MAC
observed at the capture point; for remote IPs that is commonly a gateway/next hop.
See MAC_VENDOR.md for provenance, matching rules and interpretation limits.

HOW IT WORKS

1. run.sh starts app.py using the included local Python environment.
2. Python serves the interface only on 127.0.0.1 (this computer).
3. The browser sends your selected file to that local process.
4. The server writes a randomly located temporary copy for decoding.
5. analyzer.py uses Scapy to read PCAP/PCAPNG packets and aggregate
   endpoint pairs, protocol counts, byte totals, timestamps and DNS names.
6. The temporary uploaded file is deleted after the request, including
   handled failures. The browser draws SVG charts from the JSON result.

No cloud service, telemetry, CDN, or remote scripts are used. Normal
analysis works offline. The original file is never modified. The process
still reads capture content, so use a current parser and normal non-root
user. This is a local personal tool, not a hardened multi-user web service.
Do not change its bind address to expose it to a network.

LIMITS AND HONEST INTERPRETATION

- Uploads are limited to 256 MiB. Split larger files in Wireshark/editcap.
- Analysis is capped at 500,000 packets, 20,000 endpoints and 50,000
  connections; warnings identify partial results. Read those warnings.
- The graph is intentionally a readable subset, not a network inventory.
- Common IPv4, IPv6, TCP, UDP, ICMP, ARP and DNS traffic are supported.
  Link-layer support depends on Scapy; unusual or damaged captures may
  be only partially decoded. No full Wireshark dissector parity is claimed.
- TLS/HTTPS, VPN and encrypted DNS payloads are not decrypted.
- Port numbers suggest services but do not prove which application ran.
- No general TCP-stream reassembly, IP-fragment reassembly, malware
  verdicts, passive OS detection, live capture, or device discovery.
- Capture placement, packet loss, truncation and capture filters affect
  the picture. Only traffic actually in the file can be represented.
- Byte counts describe captured traffic metadata, not application payload
  size or bandwidth measured on every link in the network.
- The examples are generated artificial data, NOT a capture of your LAN.

PROJECT FILES / FURTHER DEVELOPMENT

  app.py                  Loopback HTTP server, upload safety, app entry
  analyzer.py             Packet parsing and aggregation; analyze(path)
  static/index.html       Page structure and accessible controls
  static/style.css        Colors, spacing, responsive layout
  static/app.js           Map, filters, detail panel and charts
  examples/make_demo.py   Regenerate artificial demo capture files
  examples/demo.pcap      Sample classic PCAP
  examples/demo.pcapng    Sample Wireshark-style PCAPNG
  tests/                  Parser, server, integration and frontend tests
  requirements.txt        Runtime dependency pinned for reproducibility
  run.sh                  Linux launcher
  .venv/                  Installed Python environment for this machine

Edit the Python parser to add protocols or statistics. Keep analyze(path)
returning the documented dictionary schema at the top of analyzer.py.
Edit static/app.js to add chart interactions or alternative graph layouts.
Edit static/style.css to change the appearance. Static files are served
without caching; refresh the browser after edits. Restart the process after
Python changes.

Use tests first: add a tiny artificial capture that demonstrates the new
behavior, see the test fail, implement it, then run the whole suite. Avoid
committing private production captures as test fixtures. Treat all packet
text as untrusted: render it as text, never HTML. Keep limits visible and
never hide discarded data behind apparently complete totals.

Parser node lookup checks only the packet's at most two unique endpoints,
not every accumulated node. Metadata is built/classified only when missing.
Output ordering, counts, warnings and cap semantics are unchanged.

The node-lookup regression counts whole-map key exposure, membership checks,
metadata construction and address parsing; it has no tight timing threshold.
Run a reproducible synthetic benchmark (three runs per size):

  .venv/bin/python tests/test_node_lookup.py /tmp/packetmap-benchmark.json

Use a new output path each time; existing reports are never overwritten.
Reports include complete outputs and node/edge cap boundary cases for exact
before/after comparison. Captures are temporary; no network lookups are used.
Timing is informational, never a test threshold.

Development commands (from this folder):

  .venv/bin/python -m pytest -q
  node --test tests/test_frontend.cjs
  .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_timeline_browser.py
  .venv/bin/python examples/make_demo.py

Useful future additions: applying time ranges to topology analysis, a separate
MAC-layer map, conversation direction/handshake analysis, DNS CNAME/TTL history,
a background parser process with cancellation, and a packaged AppImage.

INSTALLING ON ANOTHER LINUX COMPUTER

Copy the source folder, but recreate .venv; virtual environments are not
portable. You need Python 3.10+ and a modern browser. Initial dependency
installation requires internet access; subsequent use does not.

Using uv, if installed:

  cd /path/to/PacketMap
  uv venv .venv
  uv pip install --python .venv/bin/python -r requirements.txt
  chmod +x run.sh
  ./run.sh

Or using standard Python (your distribution may require python3-venv):

  cd /path/to/PacketMap
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  chmod +x run.sh
  ./run.sh

For development also install pytest (and Node.js for frontend unit tests).
Playwright is only needed for browser automation, not normal app use.
The timeline browser regression starts and closes a temporary loopback server,
uploads synthetic sparse/adaptive captures, checks actual SVG zero gaps and
point bounds, and verifies the downloaded JSON including interval width.
Update the Desktop launcher's Exec and Path if you move the folder.
README.md is the canonical project guide. README.txt is an identical visible copy
for local file managers.
