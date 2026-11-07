# Installation

Requires Go 1.25 or newer.

```sh
git clone https://github.com/davezant/rbproxy
cd rbproxy
go build -o rbproxy .
./rbproxy --help
```

Run the tests:

```sh
go test ./...
```

### Listening on ports 80/443 without root

```sh
sudo setcap 'cap_net_bind_service=+ep' ./rbproxy
```

### systemd

```ini
# /etc/systemd/system/rbproxy.service
[Unit]
Description=RBProxy
After=network.target

[Service]
ExecStart=/usr/local/bin/rbproxy host --config /etc/rbproxy/rbproxy.json
WorkingDirectory=/var/lib/rbproxy
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
StateDirectory=rbproxy
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Set `"event_log": "/var/lib/rbproxy/rbproxy-events.jsonl"` in the config file so the log goes to the state directory.
