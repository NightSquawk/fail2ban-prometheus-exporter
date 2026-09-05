# Fail2Ban Prometheus Exporter

Collect metrics from a running fail2ban instance with optional geo-tagging support.

## Table of Contents
1. Quick Start
2. Metrics
3. Configuration
4. Securing the metrics endpoint
5. Building from source
6. Textfile metrics
7. Roadmap
8. Troubleshooting

## 1. Quick Start

The exporter can be run as a standalone binary or a docker container.

### 1.1. Standalone

The following command will start collecting metrics from the `/var/run/fail2ban/fail2ban.sock` file and expose them on port `9191`.

```
$ fail2ban_exporter --collector.f2b.socket=/var/run/fail2ban/fail2ban.sock --web.listen-address=":9191"

2022/02/20 09:54:06 fail2ban exporter version 0.8.1
2022/02/20 09:54:06 starting server at :9191
2022/02/20 09:54:06 reading metrics from fail2ban socket: /var/run/fail2ban/fail2ban.sock
2022/02/20 09:54:06 metrics available at '/metrics'
2022/02/20 09:54:06 ready
```

Binary files for each release can be found on the [releases](https://github.com/NightSquawk/fail2ban-prometheus-exporter/releases) page.

There is also an [example systemd service file](/_examples/systemd/fail2ban_exporter.service) included in the repository.
This is a starting point to run the exporter as a service.

### 1.2. Docker

**Docker run**
```
docker run -d \
    --name "fail2ban-exporter" \
    -v /var/run/fail2ban:/var/run/fail2ban:ro \
    -p "9191:9191" \
    ghcr.io/NightSquawk/fail2ban-prometheus-exporter:latest
```

**Docker compose**

```
version: "2"
services:
  exporter:
    image: ghcr.io/NightSquawk/fail2ban-prometheus-exporter:latest
    volumes:
    - /var/run/fail2ban/:/var/run/fail2ban:ro
    ports:
    - "9191:9191"
```

Use the `:latest` tag to get the latest stable release.

**NOTE:** While it is possible to mount the `fail2ban.sock` file directly, it is recommended to mount the parent folder instead.
The `.sock` file is deleted by fail2ban on shutdown and re-created on startup and this causes problems for the docker mount.

## 2. Metrics

The exporter exposes the following metrics:

*All metric names are prefixed with `f2b_`*

| Metric                       | Description                                                                        | Example                                             |
|------------------------------|------------------------------------------------------------------------------------|-----------------------------------------------------|
| `up`                         | Returns 1 if the exporter is up and running                                        | `f2b_up{system="hostname"} 1`                      |
| `errors_total`               | Count the number of errors since startup by type                                   |                                                     |
| `errors_total{type="socket_conn"}` | Errors connecting to the fail2ban socket (e.g. connection refused)           | `f2b_errors_total{type="socket_conn",system="hostname"} 0` |
| `errors_total{type="socket_req"}`  | Errors sending requests to the fail2ban server (e.g. invalid responses)      | `f2b_errors_total{type="socket_req",system="hostname"} 0` |
| `jail_count`                 | Number of jails exported (see [2.4](#24-filtering-jails))                          | `f2b_jail_count{system="hostname"} 2`               |
| `jail_banned_current`        | Number of IPs currently banned per jail                                            | `f2b_jail_banned_current{jail="sshd",system="hostname"} 15` |
| `jail_banned_total`          | Total number of banned IPs since fail2ban startup per jail (includes expired bans) | `f2b_jail_banned_total{jail="sshd",system="hostname"} 31` |
| `jail_failed_current`        | Number of current failures per jail                                                | `f2b_jail_failed_current{jail="sshd",system="hostname"} 6` |
| `jail_failed_total`          | Total number of failures since fail2ban startup per jail                           | `f2b_jail_failed_total{jail="sshd",system="hostname"} 125` |
| `jail_config_ban_time`       | How long an IP is banned for in this jail (in seconds)                             | `f2b_config_jail_ban_time{jail="sshd",system="hostname"} 600` |
| `jail_config_find_time`      | How far back the filter will look for failures in this jail (in seconds)           | `f2b_config_jail_find_time{jail="sshd",system="hostname"} 600` |
| `jail_config_max_retry`      | The max number of failures allowed before banning an IP in this jail               | `f2b_config_jail_max_retries{jail="sshd",system="hostname"} 5` |
| `banned_ip`                  | Currently banned IP address (value is 1 if banned)                                 | `f2b_banned_ip{jail="sshd",ip="1.2.3.4",system="hostname",city="New York",latitude="40.7128",longitude="-74.0060"} 1` |
| `version`                    | Version string of the exporter and fail2ban                                        | `f2b_version{exporter="0.5.0",fail2ban="0.11.1",system="hostname"} 1` |

The metrics above correspond to the matching fields in the `fail2ban-client status <jail>` command:
```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 6
|  |- Total failed:     125
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 15
   |- Total banned:     31
   `- Banned IP list:   ...
```

*Renamed in 1.2.0-beta:* `f2b_errors` is now `f2b_errors_total`, matching the Prometheus convention for counters. `f2b_jail_banned_total` and `f2b_jail_failed_total` kept their names but are now exposed as counters rather than gauges, and `f2b_attacks_by_hour` / `f2b_attacks_by_day_of_week` as gauges rather than counters — their values fall as bans age out of the rolling window, so they were never valid counters.

### 2.1. Grafana

The metrics exported by this tool are compatible with Prometheus and Grafana.
A sample grafana dashboard can be found in the [grafana.json](/_examples/grafana/dashboard.json) file.
Just import the contents of this file into a new Grafana dashboard to get started.

The dashboard supports displaying data from multiple exporters. Use the `instance` dashboard variable to select which ones to display.

*(Sample dashboard is compatible with Grafana `9.1.8` and above)*

### 2.2. Extended metrics

Beyond the standard socket-based metrics, the exporter can export several extra metric families.

**Database-backed metrics** (require `--collector.f2b.database`, off by default):

| Family | Metrics | Labels |
|--------|---------|--------|
| Time-based | `ban_duration_remaining_seconds`, `ban_age_seconds`, `ban_expiry_timestamp` | `jail`, `ip` |
| Historical | `ban_history_total`, `ip_ban_count_total`, `ip_first_seen_timestamp`, `ip_last_seen_timestamp`, `repeat_offender` | `ip` |
| Attack patterns | `attack_pattern_type`, `attacks_by_hour`, `attacks_by_day_of_week`, `attack_velocity`, `suspicious_pattern_score` | `pattern_type`, `jail`, `hour`, `day` |
| Alerts | `alert_high_ban_rate`, `alert_new_country_attack`, `alert_coordinated_attack`, `alert_jail_inactive`, `alert_repeat_offender_spike` | `jail`, `country_code` |

Attack patterns are heuristic: `brute_force` (3+ bans of the same IP in a jail within 48h), `port_scan` (5+ IPs banned in the same jail), and `distributed` (bans from 3+ countries in the same jail, requires geo). Alert gauges flip to 1 when the corresponding `--alert.*` threshold is crossed.

**Geographic aggregates** (require `--geo.enabled`): `attacks_by_country_total`, `attacks_by_city_total`, `top_attack_countries`, `geographic_attack_rate`.

**Collector self-metrics**: `collection_duration_seconds`, `database_query_duration_seconds`, `geo_lookup_duration_seconds`, `metrics_exported_total`, `collection_errors_total`.

**Multi-tenant labels**: every metric carries `customer_id`, `customer_name`, and `tenant_id` labels (empty strings unless set with the `--customer.*`/`--tenant.id` flags).

### 2.3. Cardinality and scrape cost

Per-IP metric families (`banned_ip`, the time-based family, and the historical family) create one time series per banned IP and are unbounded on busy hosts. Two safeguards apply:

- `--collector.f2b.max-ip-metrics` (default `500`) caps each per-IP family at the N most recent entries; set to `0` to disable the cap. Truncation is logged. Aggregate metrics (jail counts, `ban_history_total`, per-country totals) always reflect the full data set.
- `--collector.f2b.database-cache-ttl` (default `60` seconds) caches the fail2ban database query results, so a 15s Prometheus scrape interval does not run full-table SQLite scans on every scrape. Set to `0` to query on every scrape.

Database-backed metrics are **opt-in**: the exporter only opens the fail2ban database when `--collector.f2b.database` is set explicitly (the standard fail2ban path is `/var/lib/fail2ban/fail2ban.sqlite3`). If the database cannot be opened, the exporter logs a warning and continues with socket-based metrics only.

### 2.4. Filtering jails

Two regular expressions decide which jails are exported at all:

- `--collector.f2b.jail-include` — only jails whose name matches are exported (empty means all jails)
- `--collector.f2b.jail-exclude` — jails whose name matches are never exported; applied after the include rule, so exclude always wins

Both patterns are unanchored, so `auth` matches `apache-auth`; use `^...$` to match a whole jail name.

Filtering applies everywhere a jail appears: per-jail stats and config, per-IP metrics, geographic aggregates, attack patterns and alerts. It also applies to `f2b_jail_count`, which reports the number of jails this exporter exports rather than the number fail2ban has configured.

```bash
# Everything except the noisy recidive jail
fail2ban_exporter --collector.f2b.jail-exclude='^recidive$'
```

### 2.5. Anonymizing banned IP addresses

Some deployments cannot export attacker IP addresses into a metrics store. `--collector.f2b.ip-anonymize` transforms the `ip` label on `f2b_banned_ip` and on the time-based and historical per-IP families:

| Mode | `ip` label | Notes |
|------|-----------|-------|
| `none` (default) | `203.0.113.42` | The address as fail2ban reports it |
| `mask` | `203.0.113.0/24` | Truncated to `--collector.f2b.ip-mask-bits-v4` / `-v6` (defaults 24 and 64) |
| `hash` | `4f9d2c1a8b3e7605` | First 16 hex characters of a salted SHA-256 digest |

Two things are worth knowing before turning this on:

- **`mask` merges series.** Several addresses in one block become a single series per jail. `f2b_banned_ip` stays a presence indicator (value `1`) for the block, and the time-based metrics describe the most recent ban in it. `f2b_ip_ban_count_total` sums over the block.
- **`hash` needs a stable salt.** Without `--collector.f2b.ip-hash-salt` a random salt is generated per process, so every restart produces new label values and breaks series continuity. Set it explicitly for anything long-lived.

Geo lookups always use the real address, so country and city labels and the geographic aggregates are unaffected by either mode. Attack-pattern detection also uses real addresses, so brute-force detection is not weakened by masking.

## 3. Configuration

The exporter is configured with CLI flags and environment variables.
There are no configuration files.

**CLI flags**
```
Usage: fail2ban_exporter [flags]

🚀 Export prometheus metrics from a running Fail2Ban instance

Flags:
  -h, --help                           Show context-sensitive help.
  -v, --version                        Show version info and exit
      --dry-run                        Attempt to connect to the fail2ban socket then exit before
                                       starting the server
      --web.listen-address=":9191"     Address to use for the metrics server
                                       ($F2B_WEB_LISTEN_ADDRESS)
      --web.config-file=STRING         Path to a prometheus/exporter-toolkit web config file,
                                       enabling TLS, mTLS and multi-user basic auth
                                       ($F2B_WEB_CONFIG_FILE)
      --collector.f2b.socket="/var/run/fail2ban/fail2ban.sock"
                                       Path to the fail2ban server socket ($F2B_COLLECTOR_SOCKET)
      --collector.f2b.database=""      Path to the fail2ban SQLite database (e.g.
                                       /var/lib/fail2ban/fail2ban.sqlite3). Empty disables
                                       database-backed metrics ($F2B_COLLECTOR_DATABASE)
      --collector.f2b.timeout=5s       Timeout for connecting to the fail2ban socket and
                                       for each command sent over it (0 = no timeout)
                                       ($F2B_COLLECTOR_TIMEOUT)
      --collector.f2b.max-ip-metrics=500
                                       Maximum number of per-IP series to export per
                                       metric family, most recent first (0 = unlimited)
                                       ($F2B_COLLECTOR_MAX_IP_METRICS)
      --collector.f2b.database-cache-ttl=60
                                       Seconds to cache fail2ban database query results
                                       between scrapes (0 = query on every scrape)
                                       ($F2B_COLLECTOR_DATABASE_CACHE_TTL)
      --collector.f2b.jail-include=STRING
                                       Only export jails whose name matches this regular expression
                                       (empty = all jails) ($F2B_COLLECTOR_JAIL_INCLUDE)
      --collector.f2b.jail-exclude=STRING
                                       Never export jails whose name matches this regular
                                       expression, applied after --collector.f2b.jail-include
                                       ($F2B_COLLECTOR_JAIL_EXCLUDE)
      --collector.f2b.ip-anonymize="none"
                                       How to render banned IPs in the 'ip' label: none,
                                       mask (network prefix) or hash (salted digest)
                                       ($F2B_COLLECTOR_IP_ANONYMIZE)
      --collector.f2b.ip-mask-bits-v4=24
                                       Prefix length kept for IPv4 addresses
                                       when --collector.f2b.ip-anonymize=mask
                                       ($F2B_COLLECTOR_IP_MASK_BITS_V4)
      --collector.f2b.ip-mask-bits-v6=64
                                       Prefix length kept for IPv6 addresses
                                       when --collector.f2b.ip-anonymize=mask
                                       ($F2B_COLLECTOR_IP_MASK_BITS_V6)
      --collector.f2b.ip-hash-salt=STRING
                                       Salt for --collector.f2b.ip-anonymize=hash; a random salt is
                                       generated per process if empty ($F2B_COLLECTOR_IP_HASH_SALT)
      --collector.f2b.exit-on-socket-connection-error
                                       When set to true the exporter will immediately
                                       exit on a fail2ban socket connection error
                                       ($F2B_EXIT_ON_SOCKET_CONN_ERROR)
      --collector.textfile.directory=STRING
                                       Directory to read text files with metrics from
                                       ($F2B_COLLECTOR_TEXT_PATH)
      --web.basic-auth.username=STRING
                                       DEPRECATED, use --web.config-file. Username to use to protect
                                       endpoints with basic auth ($F2B_WEB_BASICAUTH_USER)
      --web.basic-auth.password=STRING
                                       DEPRECATED, use --web.config-file. Password to use to protect
                                       endpoints with basic auth ($F2B_WEB_BASICAUTH_PASS)
      --geo.enabled                    Enable geo-tagging of banned IPs ($F2B_GEO_ENABLED)
      --geo.db-path=STRING             Path to MaxMind GeoLite2-City.mmdb database file
                                       ($F2B_GEO_DB_PATH)
      --geo.provider="maxmind"         Geo provider to use (default: maxmind) ($F2B_GEO_PROVIDER)
      --customer.id=STRING             Customer identifier for multi-tenant support
                                       ($F2B_CUSTOMER_ID)
      --customer.name=STRING           Customer name for multi-tenant support ($F2B_CUSTOMER_NAME)
      --tenant.id=STRING               Tenant identifier for multi-tenant support ($F2B_TENANT_ID)
      --alert.ban-rate-threshold=10    Ban rate threshold (bans per minute) for high ban rate alert
                                       ($F2B_ALERT_BAN_RATE_THRESHOLD)
      --alert.coordinated-min-ips=5    Minimum number of IPs for coordinated attack alert
                                       ($F2B_ALERT_COORDINATED_MIN_IPS)
      --alert.jail-inactivity-hours=24
                                       Hours of inactivity before jail inactivity alert
                                       ($F2B_ALERT_JAIL_INACTIVITY_HOURS)
```

**Environment variables**

Each environment variable corresponds to a CLI flag.
If both are specified, the CLI flag takes precedence.

| Environment variable            | Corresponding CLI flag                            |
|---------------------------------|---------------------------------------------------|
| `F2B_COLLECTOR_SOCKET`          | `--collector.f2b.socket`                          |
| `F2B_COLLECTOR_DATABASE`        | `--collector.f2b.database`                        |
| `F2B_COLLECTOR_TIMEOUT`         | `--collector.f2b.timeout`                         |
| `F2B_COLLECTOR_JAIL_INCLUDE`    | `--collector.f2b.jail-include`                    |
| `F2B_COLLECTOR_JAIL_EXCLUDE`    | `--collector.f2b.jail-exclude`                    |
| `F2B_COLLECTOR_IP_ANONYMIZE`    | `--collector.f2b.ip-anonymize`                    |
| `F2B_COLLECTOR_IP_MASK_BITS_V4` | `--collector.f2b.ip-mask-bits-v4`                 |
| `F2B_COLLECTOR_IP_MASK_BITS_V6` | `--collector.f2b.ip-mask-bits-v6`                 |
| `F2B_COLLECTOR_IP_HASH_SALT`    | `--collector.f2b.ip-hash-salt`                    |
| `F2B_COLLECTOR_MAX_IP_METRICS`  | `--collector.f2b.max-ip-metrics`                  |
| `F2B_COLLECTOR_DATABASE_CACHE_TTL` | `--collector.f2b.database-cache-ttl`           |
| `F2B_COLLECTOR_TEXT_PATH`       | `--collector.textfile.directory`                  |
| `F2B_WEB_LISTEN_ADDRESS`        | `--web.listen-address`                            |
| `F2B_WEB_CONFIG_FILE`           | `--web.config-file`                               |
| `F2B_WEB_BASICAUTH_USER`        | `--web.basic-auth.username`                       |
| `F2B_WEB_BASICAUTH_PASS`        | `--web.basic-auth.password`                       |
| `F2B_EXIT_ON_SOCKET_CONN_ERROR` | `--collector.f2b.exit-on-socket-connection-error` |
| `F2B_GEO_ENABLED`               | `--geo.enabled`                                   |
| `F2B_GEO_DB_PATH`               | `--geo.db-path`                                   |
| `F2B_GEO_PROVIDER`              | `--geo.provider`                                  |
| `F2B_CUSTOMER_ID`               | `--customer.id`                                   |
| `F2B_CUSTOMER_NAME`             | `--customer.name`                                 |
| `F2B_TENANT_ID`                 | `--tenant.id`                                     |
| `F2B_ALERT_BAN_RATE_THRESHOLD`  | `--alert.ban-rate-threshold`                      |
| `F2B_ALERT_COORDINATED_MIN_IPS` | `--alert.coordinated-min-ips`                     |
| `F2B_ALERT_JAIL_INACTIVITY_HOURS` | `--alert.jail-inactivity-hours`                 |

## 4. Securing the metrics endpoint

Point `--web.config-file` at a [prometheus/exporter-toolkit](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) web configuration file to enable TLS, mutual TLS and basic auth with bcrypt-hashed passwords:

```yaml
# web-config.yml
tls_server_config:
  cert_file: /etc/fail2ban-exporter/cert.pem
  key_file: /etc/fail2ban-exporter/key.pem
  # Optional: require client certificates (mTLS)
  # client_auth_type: RequireAndVerifyClientCert
  # client_ca_file: /etc/fail2ban-exporter/ca.pem

basic_auth_users:
  # htpasswd -nBC 12 "" | tr -d ':\n'
  prometheus: $2a$12$hNv... 
```

```bash
fail2ban_exporter --web.config-file=/etc/fail2ban-exporter/web-config.yml
```

The file is re-read on every request, so credentials and certificates can be rotated without restarting the exporter.

**Deprecated:** `--web.basic-auth.username` and `--web.basic-auth.password` still work, but they transmit credentials over plaintext HTTP and only support a single user with a plaintext password. They cannot be combined with `--web.config-file`; the exporter exits with an error if both are given.

### 4.1. Scrape timeouts

A wedged fail2ban server used to hang a scrape indefinitely, and because a collection holds a lock for its whole duration, every following scrape queued behind it. Two timeouts now bound this:

- `--collector.f2b.timeout` (default `5s`) bounds connecting to the fail2ban socket and each individual command sent over it. Set it to `0` to restore the old unbounded behaviour.
- The `X-Prometheus-Scrape-Timeout-Seconds` header that Prometheus sends on every scrape bounds the whole gather. If it is exceeded the exporter returns `503` instead of holding the connection open.

## 5. Building from source

Building from source has the following dependencies:
- Go v1.20
- Make

From there, simply run `make build`

This will download the necessary dependencies and build a `fail2ban_exporter` binary in the root of the project.

### 5.2. Geo-Tagging Setup

To enable geo-tagging of banned IPs:

1. Sign up for a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Download the GeoLite2-City database (MMDB format)
3. Provide the path to the database file using `--geo.db-path` flag
4. Enable geo-tagging with `--geo.enabled` flag

Example:
```bash
fail2ban_exporter \
  --collector.f2b.socket=/var/run/fail2ban/fail2ban.sock \
  --geo.enabled \
  --geo.db-path=/path/to/GeoLite2-City.mmdb
```

When geo-tagging is enabled, the `f2b_banned_ip` metric will include additional labels:
- `city` - City name
- `latitude` - Latitude coordinate
- `longitude` - Longitude coordinate
- `country` - Country name
- `country_code` - ISO country code

### 5.3. System Name Label

All metrics now include a `system` label with the hostname of the machine running the exporter. This allows you to distinguish metrics from multiple exporters in a Prometheus setup.

## 6. Textfile metrics

For more flexibility the exporter also allows exporting metrics collected from a text file.

To enable textfile metrics provide the directory to read files from with the `--collector.textfile.directory` flag.

Each `.prom` file is parsed as Prometheus text exposition format and its samples are exported alongside the exporter's own metrics. Counters, gauges, untyped metrics, summaries, histograms and explicit timestamps are all supported.

A file that cannot be read or parsed is skipped rather than breaking the scrape, and a file that redefines a metric family another file already defined is skipped too — the first file to define a name wins. Either case is reported through `textfile_error`:

```
# HELP textfile_error Checks for errors while reading text files
# TYPE textfile_error gauge
textfile_error{path="file.prom"} 0
```

*Prior to 1.2.0-beta these files were appended to the HTTP response after the response body had already been written and compressed, which corrupted the payload for any scraper sending `Accept-Encoding: gzip` — which Prometheus always does.*

**NOTE:** Any file not ending with `.prom` will be ignored.

**Running in Docker**

To collect textfile metrics inside a docker container, a couple of things need to be done:
1. Mount the folder with the metrics files
2. Set the `F2B_COLLECTOR_TEXT_PATH` environment variable

*For example:*
```
docker run -d \
    --name "fail2ban-exporter" \
    -v /var/run/fail2ban:/var/run/fail2ban:ro \
    -v /path/to/metrics:/app/metrics/:ro \
    -e F2B_COLLECTOR_TEXT_PATH=/app/metrics \
    -p "9191:9191" \
    ghcr.io/NightSquawk/fail2ban-prometheus-exporter:latest
```

## 7. Roadmap

Planned work is tracked in [ROADMAP.md](ROADMAP.md): geo improvements (ASN
labels, lookup caching, database reload), structured logging, multiple fail2ban
targets per exporter, fail2ban configuration metrics, a purge-proof ban counter,
packaging and supply-chain hardening, and example Prometheus alerting rules.

## 8. Troubleshooting

### 8.1. "no such file or directory"

```
error opening socket: dial unix /var/run/fail2ban/fail2ban.sock: connect: no such file or directory
```

There are a couple of potential causes for the error above.

**File not found**

The first is that the file does not exist, so first check that the file path shown in the error actually exists on the system running the exporter.
The fail2ban server may be storing the socket file in another location on your machine.

If you are using docker, make sure the correct host folder was mounted to the correct location.

If the file is not in the expected location, you can run the exporter with the corresponding CLI flag or environment variable to use a different file path.

**Permissions**

If the file does exist, the likely cause are file permissions.
By default, the fail2ban server runs as the `root` user and the socket file can only be accessed by the same user.
If you are running the exporter as a non-root user, it will not be able to open the socket file to read/write commands to the server, leading to the error above.

In this case there are a few solutions:
1. Run the exporter as the same user as fail2ban (usually `root`)
2. Update the fail2ban server config to run as a non-root user, then run the exporter as the same user
3. Update the socket file permissions to be less restrictive

I would recommend option `1.` since it is the simplest. Option `2.` is a bit more complex, check the [fail2ban server documentation](https://coderwall.com/p/haj28a/running-rootless-fail2ban-on-debian) for more details. And option `3.` is just a temporary fix. The socket file gets re-created each time the fail2ban server is restarted and the original permissions will be restored, so you will need to update the permissions every time the server restarts.
