<h1>⟁ wspectre</h1>

<em>hear what the wire is really saying.</em>

A websocket reconnaissance tool. Point it at a socket and it tells you what
an app is actually transmitting — frame by frame, encoding decoded, cadence
exposed. For reverse-engineering, bug bounty, and anyone who wants to read
the conversation an app is having about them.

```
pipx install git+https://github.com/SaxxSaxx/wspectre
```

### listen

```
$ wspectre listen wss://target/socket --origin https://target --send '{"op":"hello"}' --save open.jsonl

↑    0.001  text          {"op":"hello"}
↓    0.044  json          {"t":"welcome","heartbeat":5000}
↓    5.061  text          0                                          ← keepalive
↓   10.072  text          0
↓   15.084  json          {"t":"presence","state":1}

heartbeat: 5.01s ×3  (confidence 0.75)
```

It decodes **json · msgpack · gzip · base64** on sight, and flags periodic
frames so the keepalive / presence cadence falls out on its own.

### compare two states

The difference between two captures is usually the whole protocol.

```
$ wspectre diff open.jsonl half-swiped.jsonl

+ down  json         <=64      (appears only in B)
- up    binary       <=16      (gone in B)
```

Capture a socket in state A, capture it in state B, and `diff` shows you
exactly which frames the state change moved.

### show a capture

```
$ wspectre show open.jsonl
```

---

Reads only. No telemetry, no accounts — it listens, it never phones home.
For research and authorized testing.

<sub>♄</sub>
