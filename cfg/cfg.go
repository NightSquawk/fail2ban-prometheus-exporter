package cfg

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/auth"
	"github.com/alecthomas/kong"
)

var cliStruct struct {
	VersionMode              bool          `name:"version" short:"v" help:"Show version info and exit"`
	DryRunMode               bool          `name:"dry-run" help:"Attempt to connect to the fail2ban socket then exit before starting the server"`
	ServerAddress            string        `name:"web.listen-address" env:"F2B_WEB_LISTEN_ADDRESS" help:"Address to use for the metrics server" default:"${default_address}"`
	WebConfigFile            string        `name:"web.config-file" env:"F2B_WEB_CONFIG_FILE" help:"Path to a prometheus/exporter-toolkit web config file, enabling TLS, mTLS and multi-user basic auth"`
	F2bSocketPath            string        `name:"collector.f2b.socket" env:"F2B_COLLECTOR_SOCKET" help:"Path to the fail2ban server socket" default:"${default_socket}"`
	F2bDatabasePath          string        `name:"collector.f2b.database" env:"F2B_COLLECTOR_DATABASE" help:"Path to the fail2ban SQLite database (e.g. /var/lib/fail2ban/fail2ban.sqlite3). Empty disables database-backed metrics" default:"${default_database}"`
	F2bTimeout               time.Duration `name:"collector.f2b.timeout" env:"F2B_COLLECTOR_TIMEOUT" help:"Timeout for connecting to the fail2ban socket and for each command sent over it (0 = no timeout)" default:"5s"`
	F2bMaxIPMetrics          int           `name:"collector.f2b.max-ip-metrics" env:"F2B_COLLECTOR_MAX_IP_METRICS" help:"Maximum number of per-IP series to export per metric family, most recent first (0 = unlimited)" default:"500"`
	F2bDatabaseCacheTTL      int           `name:"collector.f2b.database-cache-ttl" env:"F2B_COLLECTOR_DATABASE_CACHE_TTL" help:"Seconds to cache fail2ban database query results between scrapes (0 = query on every scrape)" default:"60"`
	F2bJailInclude           string        `name:"collector.f2b.jail-include" env:"F2B_COLLECTOR_JAIL_INCLUDE" help:"Only export jails whose name matches this regular expression (empty = all jails)"`
	F2bJailExclude           string        `name:"collector.f2b.jail-exclude" env:"F2B_COLLECTOR_JAIL_EXCLUDE" help:"Never export jails whose name matches this regular expression, applied after --collector.f2b.jail-include"`
	F2bIPAnonymize           string        `name:"collector.f2b.ip-anonymize" env:"F2B_COLLECTOR_IP_ANONYMIZE" help:"How to render banned IPs in the 'ip' label: none, mask (network prefix) or hash (salted digest)" enum:"none,mask,hash" default:"none"`
	F2bIPMaskBitsV4          int           `name:"collector.f2b.ip-mask-bits-v4" env:"F2B_COLLECTOR_IP_MASK_BITS_V4" help:"Prefix length kept for IPv4 addresses when --collector.f2b.ip-anonymize=mask" default:"24"`
	F2bIPMaskBitsV6          int           `name:"collector.f2b.ip-mask-bits-v6" env:"F2B_COLLECTOR_IP_MASK_BITS_V6" help:"Prefix length kept for IPv6 addresses when --collector.f2b.ip-anonymize=mask" default:"64"`
	F2bIPHashSalt            string        `name:"collector.f2b.ip-hash-salt" env:"F2B_COLLECTOR_IP_HASH_SALT" help:"Salt for --collector.f2b.ip-anonymize=hash; a random salt is generated per process if empty"`
	ExitOnSocketError        bool          `name:"collector.f2b.exit-on-socket-connection-error" env:"F2B_EXIT_ON_SOCKET_CONN_ERROR" help:"When set to true the exporter will immediately exit on a fail2ban socket connection error"`
	TextFileExporterPath     string        `name:"collector.textfile.directory" env:"F2B_COLLECTOR_TEXT_PATH" help:"Directory to read text files with metrics from"`
	BasicAuthUser            string        `name:"web.basic-auth.username" env:"F2B_WEB_BASICAUTH_USER" help:"DEPRECATED, use --web.config-file. Username to use to protect endpoints with basic auth"`
	BasicAuthPass            string        `name:"web.basic-auth.password" env:"F2B_WEB_BASICAUTH_PASS" help:"DEPRECATED, use --web.config-file. Password to use to protect endpoints with basic auth"`
	GeoEnabled               bool          `name:"geo.enabled" env:"F2B_GEO_ENABLED" help:"Enable geo-tagging of banned IPs"`
	GeoDBPath                string        `name:"geo.db-path" env:"F2B_GEO_DB_PATH" help:"Path to MaxMind GeoLite2-City.mmdb database file"`
	GeoProvider              string        `name:"geo.provider" env:"F2B_GEO_PROVIDER" help:"Geo provider to use (default: maxmind)" default:"maxmind"`
	CustomerID               string        `name:"customer.id" env:"F2B_CUSTOMER_ID" help:"Customer identifier for multi-tenant support"`
	CustomerName             string        `name:"customer.name" env:"F2B_CUSTOMER_NAME" help:"Customer name for multi-tenant support"`
	TenantID                 string        `name:"tenant.id" env:"F2B_TENANT_ID" help:"Tenant identifier for multi-tenant support"`
	AlertBanRateThreshold    float64       `name:"alert.ban-rate-threshold" env:"F2B_ALERT_BAN_RATE_THRESHOLD" help:"Ban rate threshold (bans per minute) for high ban rate alert" default:"10"`
	AlertCoordinatedMinIPs   int           `name:"alert.coordinated-min-ips" env:"F2B_ALERT_COORDINATED_MIN_IPS" help:"Minimum number of IPs for coordinated attack alert" default:"5"`
	AlertJailInactivityHours int           `name:"alert.jail-inactivity-hours" env:"F2B_ALERT_JAIL_INACTIVITY_HOURS" help:"Hours of inactivity before jail inactivity alert" default:"24"`
}

func Parse() *AppSettings {
	ctx := kong.Parse(
		&cliStruct,
		kong.Vars{
			"default_socket":   "/var/run/fail2ban/fail2ban.sock",
			"default_address":  ":9191",
			"default_database": "",
		},
		kong.Name("fail2ban_exporter"),
		kong.Description("🚀 Export prometheus metrics from a running Fail2Ban instance"),
		kong.UsageOnError(),
	)

	validateFlags(ctx)
	settings := &AppSettings{
		VersionMode:           cliStruct.VersionMode,
		DryRunMode:            cliStruct.DryRunMode,
		MetricsAddress:        cliStruct.ServerAddress,
		WebConfigFile:         cliStruct.WebConfigFile,
		Fail2BanSocketPath:    cliStruct.F2bSocketPath,
		Fail2BanDatabasePath:  cliStruct.F2bDatabasePath,
		Fail2BanTimeout:       cliStruct.F2bTimeout,
		MaxIPMetrics:          cliStruct.F2bMaxIPMetrics,
		DatabaseCacheTTL:      cliStruct.F2bDatabaseCacheTTL,
		FileCollectorPath:     cliStruct.TextFileExporterPath,
		ExitOnSocketConnError: cliStruct.ExitOnSocketError,
		AuthProvider:          createAuthProvider(),
		Geo: GeoSettings{
			Enabled:  cliStruct.GeoEnabled,
			DBPath:   cliStruct.GeoDBPath,
			Provider: cliStruct.GeoProvider,
		},
		Customer: CustomerSettings{
			ID:       cliStruct.CustomerID,
			Name:     cliStruct.CustomerName,
			TenantID: cliStruct.TenantID,
		},
		Alert: AlertSettings{
			HighBanRateThreshold:    cliStruct.AlertBanRateThreshold,
			CoordinatedAttackMinIPs: cliStruct.AlertCoordinatedMinIPs,
			JailInactivityHours:     cliStruct.AlertJailInactivityHours,
		},
		Filter: FilterSettings{
			JailInclude: mustCompileOrNil(cliStruct.F2bJailInclude),
			JailExclude: mustCompileOrNil(cliStruct.F2bJailExclude),
		},
		Privacy: PrivacySettings{
			Mode:       AnonymizeMode(cliStruct.F2bIPAnonymize),
			MaskBitsV4: cliStruct.F2bIPMaskBitsV4,
			MaskBitsV6: cliStruct.F2bIPMaskBitsV6,
			HashSalt:   cliStruct.F2bIPHashSalt,
		},
	}
	return settings
}

// mustCompileOrNil compiles pattern, returning nil for the empty string.
// validateFlags has already rejected patterns that do not compile.
func mustCompileOrNil(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	return regexp.MustCompile(pattern)
}

func createAuthProvider() auth.AuthProvider {
	username := cliStruct.BasicAuthUser
	password := cliStruct.BasicAuthPass

	if len(username) == 0 && len(password) == 0 {
		return auth.NewEmptyAuthProvider()
	}
	log.Print("basic auth enabled (--web.basic-auth.* is deprecated, use --web.config-file for TLS and hashed credentials)")
	return auth.NewBasicAuthProvider(username, password)
}

func validateFlags(cliCtx *kong.Context) {
	var flagsValid = true
	var messages = []string{}
	if !cliStruct.VersionMode {
		if cliStruct.F2bSocketPath == "" {
			messages = append(messages, "error: fail2ban socket path must not be blank")
			flagsValid = false
		}
		if cliStruct.ServerAddress == "" {
			messages = append(messages, "error: invalid server address, must not be blank")
			flagsValid = false
		}
		if (len(cliStruct.BasicAuthUser) > 0) != (len(cliStruct.BasicAuthPass) > 0) {
			messages = append(messages, "error: to enable basic auth both the username and the password must be provided")
			flagsValid = false
		}
		if len(cliStruct.BasicAuthUser) > 0 && len(cliStruct.WebConfigFile) > 0 {
			messages = append(messages, "error: --web.basic-auth.* and --web.config-file are mutually exclusive, configure basic auth in the web config file")
			flagsValid = false
		}
		if cliStruct.F2bTimeout < 0 {
			messages = append(messages, "error: fail2ban socket timeout must not be negative")
			flagsValid = false
		}
		for flag, pattern := range map[string]string{
			"--collector.f2b.jail-include": cliStruct.F2bJailInclude,
			"--collector.f2b.jail-exclude": cliStruct.F2bJailExclude,
		} {
			if pattern == "" {
				continue
			}
			if _, err := regexp.Compile(pattern); err != nil {
				messages = append(messages, fmt.Sprintf("error: invalid regular expression for %s: %v", flag, err))
				flagsValid = false
			}
		}
		if cliStruct.F2bIPMaskBitsV4 < 0 || cliStruct.F2bIPMaskBitsV4 > 32 {
			messages = append(messages, "error: --collector.f2b.ip-mask-bits-v4 must be between 0 and 32")
			flagsValid = false
		}
		if cliStruct.F2bIPMaskBitsV6 < 0 || cliStruct.F2bIPMaskBitsV6 > 128 {
			messages = append(messages, "error: --collector.f2b.ip-mask-bits-v6 must be between 0 and 128")
			flagsValid = false
		}
	}
	if !flagsValid {
		cliCtx.PrintUsage(false)
		fmt.Println()
		for i := 0; i < len(messages); i++ {
			fmt.Println(messages[i])
		}
		os.Exit(1)
	}
}
