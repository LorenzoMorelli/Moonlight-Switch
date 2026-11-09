# Tailscale in Moonlight-Switch

This build embeds a Tailscale client directly in the app, so the Switch can
reach your streaming PC from any network (mobile hotspot, CGNAT, hotel Wi-Fi)
without routers, VPS or relay PCs. It works with the official Tailscale
control server and with self-hosted Headscale.

## 1. Requirements

- A Nintendo Switch running homebrew, with Wi-Fi.
- A Moonlight-Switch build with Tailscale support (`Moonlight.nro`).
- A PC running a GameStream host (Sunshine or Wolf), working on the LAN.
- A Tailscale account or a Headscale server.

## 2. Installation

Copy `Moonlight.nro` to `sdmc:/switch/`, as for a regular Moonlight-Switch
install.

## 3. Prepare the PC and the tailnet

1. Install Tailscale on the streaming PC and log in to your tailnet. Check it
   has a `100.x.y.z` address (`tailscale ip`).
2. Allow the Tailscale interface through the PC firewall on:
   - TCP 47984, 47989, 48010
   - UDP 47998, 47999, 48000, 48002, 48010
3. Keep the host's packet size at 1200 bytes or less (Sunshine's default of
   1024 is fine): the tunnel MTU is 1280.
4. With default ACLs nothing else is needed. With restrictive ACLs, allow the
   Switch to reach the PC on the ports above.
5. Optional: create an auth key (admin console → Settings → Keys). Reusable
   and pre-approved keys make registration hands-free. With Headscale:
   `headscale preauthkeys create --user <user> --reusable`.

## 4. First launch

1. Open the **Tailscale** tab.
2. Headscale only: set **Control server URL**. For Tailscale, keep the default.
3. Log in with either:
   - **Login with auth key**: type the `tskey-auth-...` / `hskey-...` key; or
   - **Login via browser URL**: open the displayed URL on a phone or PC and
     authorize the Switch.
4. Turn on **Enabled**. Within about 20 seconds the state becomes
   **Connected** and shows the Switch's `100.x` address.

The auth key is not kept after registration; on later launches the Switch
reconnects with its saved node keys.

## 5. Add the PC and stream

1. The PC appears under **Devices in your tailnet** with its `100.x` address.
2. In **Add host**, enter that address (or the MagicDNS name).
3. Pair with the PIN as usual, then start streaming.

LAN hosts found via mDNS, Wake-on-LAN and local streaming keep working with
Tailscale enabled. Off-LAN, the connection upgrades to a **direct** path when
NAT allows it (usually within 30 seconds), otherwise it stays on a **DERP**
relay, which adds latency but still works.

Enable Tailscale before launching the app when you plan to stream over it:
the larger network receive buffer used for tunneled video is set up at
startup only when Tailscale is enabled.

## 6. Diagnostics

The **Diagnostics** section shows the control state, the Switch address and,
for each peer, whether it is online, whether the WireGuard session is up and
the current path (`direct <ip:port>` or `derp-N`). The full log is at
`sdmc:/switch/Moonlight-Switch/tailscale/tsnet.log`.

| Symptom | Check |
|---|---|
| Stuck on "Connecting..." | Control server URL, Wi-Fi, auth key validity. |
| "Login required" | The auth key expired or was single-use: create a new one. |
| PC missing from the device list | Is the PC online in the same tailnet? |
| Pairing fails | PC firewall: TCP 47984/47989/48010 on the Tailscale interface. |
| Stream starts then freezes | Host packet size ≤ 1200; try a lower bitrate. |
| Never goes direct | Normal behind symmetric NATs; DERP streaming still works. |

To disconnect, turn **Enabled** off. **Logout** also deletes the keys.

## 7. Security and privacy

- TLS to the control server and DERP relays is always verified against the
  bundled Mozilla CA list; there is no "insecure" option.
- No telemetry: logs stay on the SD card.
- Keys are stored only in `sdmc:/switch/Moonlight-Switch/tailscale/`.
