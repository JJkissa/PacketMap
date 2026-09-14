# Offline observed-MAC attribution

Install/update explicitly from the project directory (Python 3 and curl):

```sh
python3 scripts/install_mac_vendors.py
```

Only this command accesses the network, downloading the current complete CSV. Analysis performs no per-MAC requests, DNS queries or device probes. `data/mac-vendors.csv` and `data/mac-vendors-source.json` are gitignored local files; provenance records source URL, download URL, source update date, UTC retrieval time, row count, bytes and SHA-256. Existing analyses must be reloaded to see updates. Missing/unreadable databases leave counters intact and return explicit unavailable annotations.

Source: [MACLookup CSV database](https://maclookup.app/downloads/csv-database), derived from IEEE and third-party registries. [Terms and Conditions](https://maclookup.app/terms-and-conditions) checked 10 September 2026: free lawful personal/commercial service use, API data use permitted, source attribution recommended on redistribution/display. No separate explicit bulk CSV redistribution license was confirmed. **Do not bundle or publish the CSV without separately confirming publication rights.** This application attributes MACLookup; its software license does not license the registry data.

Matching uses longest prefixes: MA-S/IAB 36 bits, MA-M 28 bits, MA-L 24 bits. CID is not a global hardware identity. Untyped database entries are not treated as allocations. Private entries suppress vendor and device hint; no fallback to a less-specific vendor. Only complete 48-bit colon, hyphen or unseparated hexadecimal MACs are accepted. Multicast, broadcast and locally administered addresses never yield reliable vendor identity. A locally administered address may be randomized, manually assigned or virtual: it is not proof of any of those.

Each node keeps its original bounded `macs` and receives a parallel `mac_vendor` list after packet processing. The parsed database is cached by file mtime/size (two versions maximum); address lookups use three dictionary probes and no per-address cache. Device hints are low-confidence vendor-category suggestions only: Apple means possible general consumer device, not iPhone; virtual vendors suggest possible VM/adapter; network vendors suggest possible network equipment. Others remain unclassified.

**Observed Ethernet addresses can belong to a gateway/next hop, especially for remote IPs. Neither the vendor allocation nor a hint identifies the remote endpoint, proves hardware ownership, or names an exact model.** Every record and the endpoint inspector carry this caution. Inspector text is rendered using `textContent`, not HTML.
