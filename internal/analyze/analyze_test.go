package analyze

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

func TestOptionsFromEnvironmentUsesSDKDefaultPaths(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	options := OptionsFromEnvironment("")
	if options.ConfigPath != awsconfig.DefaultSharedConfigFilename() {
		t.Fatalf("config path = %q, want SDK default %q", options.ConfigPath, awsconfig.DefaultSharedConfigFilename())
	}
	if options.CredentialsPath != awsconfig.DefaultSharedCredentialsFilename() {
		t.Fatalf("credentials path = %q, want SDK default %q", options.CredentialsPath, awsconfig.DefaultSharedCredentialsFilename())
	}
}

func TestOptionsFromEnvironmentUsesPathOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "custom config")
	credentialsPath := filepath.Join(t.TempDir(), "custom credentials")
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)

	options := OptionsFromEnvironment("")
	if options.ConfigPath != configPath {
		t.Fatalf("config path = %q, want %q", options.ConfigPath, configPath)
	}
	if options.CredentialsPath != credentialsPath {
		t.Fatalf("credentials path = %q, want %q", options.CredentialsPath, credentialsPath)
	}
}

func TestOptionsFromEnvironmentSelectsRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "primary-region")
	t.Setenv("AWS_DEFAULT_REGION", "fallback-region")

	if region := OptionsFromEnvironment("").Region; region != "primary-region" {
		t.Fatalf("region = %q, want primary-region", region)
	}

	t.Setenv("AWS_REGION", "")
	if region := OptionsFromEnvironment("").Region; region != "fallback-region" {
		t.Fatalf("region = %q, want fallback-region", region)
	}
}

func TestAnalyzeSelectsRegion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		option     string
		config     string
		wantRegion string
	}{
		{name: "environment region", option: "environment-region", config: "[profile example]\nregion = config-region\n", wantRegion: "environment-region"},
		{name: "shared config region", config: "[profile example]\nregion = config-region\n", wantRegion: "config-region"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configPath, credentialsPath := writeSharedFiles(t, test.config, staticCredentials("example"))
			result, err := Analyze(context.Background(), Options{
				Environment:     map[string]string{"AWS_PROFILE": "example"},
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
				Region:          test.option,
			})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if result.Region != test.wantRegion {
				t.Fatalf("region = %q, want %q", result.Region, test.wantRegion)
			}
		})
	}
}

func TestProfileSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		explicit    string
		environment map[string]string
		wantProfile string
		wantSource  string
	}{
		{name: "explicit profile", explicit: "explicit", environment: map[string]string{"AWS_PROFILE": "primary", "AWS_DEFAULT_PROFILE": "fallback"}, wantProfile: "explicit", wantSource: "--profile"},
		{name: "AWS_PROFILE", environment: map[string]string{"AWS_PROFILE": "primary", "AWS_DEFAULT_PROFILE": "fallback"}, wantProfile: "primary", wantSource: "AWS_PROFILE"},
		{name: "AWS_DEFAULT_PROFILE", environment: map[string]string{"AWS_DEFAULT_PROFILE": "fallback"}, wantProfile: "fallback", wantSource: "AWS_DEFAULT_PROFILE"},
		{name: "default profile", environment: map[string]string{}, wantProfile: "default", wantSource: "default"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			profile, source := selectProfile(Options{ExplicitProfile: test.explicit, Environment: test.environment})
			if profile != test.wantProfile {
				t.Fatalf("profile = %q, want %q", profile, test.wantProfile)
			}
			if source != test.wantSource {
				t.Fatalf("source = %q, want %q", source, test.wantSource)
			}
		})
	}
}

func TestCredentialPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		explicitProfile string
		environment     map[string]string
		config          string
		credentials     string
		wantStates      map[string]State
		wantError       error
	}{
		{
			name:        "environment shadows both shared files",
			environment: completeEnvironment("example"),
			config:      staticConfig("example"),
			credentials: staticCredentials("example"),
			wantStates:  map[string]State{"environment": StateSelected, "shared-credentials": StateShadowed, "shared-config": StateShadowed},
		},
		{
			name:            "explicit profile overrides environment",
			explicitProfile: "example",
			environment:     completeEnvironment("other"),
			credentials:     staticCredentials("example"),
			wantStates:      map[string]State{"environment": StateIgnored, "shared-credentials": StateSelected, "shared-config": StateIgnored},
		},
		{
			name:        "credentials file shadows config file",
			environment: map[string]string{"AWS_PROFILE": "example"},
			config:      staticConfig("example"),
			credentials: staticCredentials("example"),
			wantStates:  map[string]State{"environment": StateIgnored, "shared-credentials": StateSelected, "shared-config": StateShadowed},
		},
		{
			name:        "partial environment falls back to config",
			environment: map[string]string{"AWS_PROFILE": "example", "AWS_ACCESS_KEY_ID": "example-access-key"},
			config:      staticConfig("example"),
			wantStates:  map[string]State{"environment": StateIgnored, "shared-credentials": StateIgnored, "shared-config": StateSelected},
		},
		{
			name:        "missing shared files",
			environment: map[string]string{},
			wantStates:  map[string]State{"environment": StateIgnored, "shared-credentials": StateIgnored, "shared-config": StateIgnored},
			wantError:   ErrNoCredentials,
		},
		{
			name:            "explicit profile is missing",
			explicitProfile: "missing",
			environment:     completeEnvironment("other"),
			wantStates:      map[string]State{"environment": StateIgnored, "shared-credentials": StateIgnored, "shared-config": StateIgnored},
			wantError:       ErrProfileNotFound,
		},
		{
			name:        "missing environment profile does not override environment credentials",
			environment: completeEnvironment("missing"),
			wantStates:  map[string]State{"environment": StateSelected, "shared-credentials": StateIgnored, "shared-config": StateIgnored},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configPath, credentialsPath := writeSharedFiles(t, test.config, test.credentials)
			result, err := Analyze(context.Background(), Options{
				ExplicitProfile: test.explicitProfile,
				Environment:     test.environment,
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}

			for source, wantState := range test.wantStates {
				finding := findingForSource(t, result, source)
				if finding.State != wantState {
					t.Errorf("%s state = %q, want %q", source, finding.State, wantState)
				}
			}
		})
	}
}

func TestPartialSharedCredentialsAreAnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      string
		credentials string
		source      string
	}{
		{name: "config file", config: "[profile example]\naws_access_key_id = example-access-key\n", source: "shared-config"},
		{name: "credentials file", credentials: "[example]\naws_access_key_id = example-access-key\n", source: "shared-credentials"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configPath, credentialsPath := writeSharedFiles(t, test.config, test.credentials)
			result, err := Analyze(context.Background(), Options{
				Environment:     map[string]string{"AWS_PROFILE": "example"},
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if err == nil {
				t.Fatal("expected an error for partial shared credentials")
			}
			if finding := findingForSource(t, result, test.source); finding.Reason != "invalid or unreadable shared AWS file" {
				t.Fatalf("reason = %q", finding.Reason)
			}
		})
	}
}

func TestCredentialProcessIsNotExecuted(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	marker := filepath.Join(root, "must-not-exist")
	configBody := "[profile example]\ncredential_process = create-file " + marker + "\n"
	configPath, credentialsPath := writeSharedFiles(t, configBody, "")

	result, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "example"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedProvider)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("credential_process appears to have been executed: %v", statErr)
	}

	finding := findingForSource(t, result, "shared-config")
	if finding.Type != "credential-process" || finding.State != StateIgnored {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestAnalyzeAssumeRoleSourceProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		configBody       string
		credentialsBody  string
		wantSourceType   string
		wantSourceReason string
	}{
		{
			name:             "static source in credentials file",
			configBody:       roleConfig("source"),
			credentialsBody:  staticCredentials("source"),
			wantSourceType:   "static",
			wantSourceReason: "source_profile resolves via shared-credentials",
		},
		{
			name:             "static source in config file",
			configBody:       roleConfig("source") + staticConfig("source"),
			wantSourceType:   "static",
			wantSourceReason: "source_profile resolves via shared-config",
		},
		{
			name: "modern SSO source",
			configBody: roleConfig("source") +
				"[profile source]\nsso_session = example-session\nsso_account_id = 000000000000\nsso_role_name = ExampleRole\n" +
				"[sso-session example-session]\nsso_start_url = https://example.invalid/start\nsso_region = example-region\n",
			wantSourceType:   "sso",
			wantSourceReason: "modern SSO source_profile selected",
		},
		{
			name:             "legacy SSO source",
			configBody:       roleConfig("source") + legacySSOConfig("source"),
			wantSourceType:   "sso",
			wantSourceReason: "legacy SSO source_profile selected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configPath, credentialsPath := writeSharedFiles(t, test.configBody, test.credentialsBody)
			result, err := Analyze(context.Background(), Options{
				ExplicitProfile: "example",
				Environment:     completeEnvironment("other"),
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			role := findingForType(t, result, "assume-role")
			if role.State != StateSelected || role.Reason != "role_arn with direct source_profile selected" {
				t.Fatalf("role finding = %#v", role)
			}
			source := findingForSource(t, result, "source-profile")
			if source.State != StateSelected || source.Type != test.wantSourceType || source.Reason != test.wantSourceReason {
				t.Fatalf("source finding = %#v", source)
			}
		})
	}
}

func TestAssumeRoleProfileSelectionSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		explicit    string
		environment map[string]string
		wantSource  string
	}{
		{name: "explicit profile", explicit: "example", environment: completeEnvironment("other"), wantSource: "--profile"},
		{name: "AWS_PROFILE", environment: map[string]string{"AWS_PROFILE": "example", "AWS_DEFAULT_PROFILE": "other"}, wantSource: "AWS_PROFILE"},
		{name: "AWS_DEFAULT_PROFILE", environment: map[string]string{"AWS_DEFAULT_PROFILE": "example"}, wantSource: "AWS_DEFAULT_PROFILE"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configPath, credentialsPath := writeSharedFiles(t, roleConfig("source")+staticConfig("source"), "")
			result, err := Analyze(context.Background(), Options{
				ExplicitProfile: test.explicit,
				Environment:     test.environment,
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if result.ProfileSource != test.wantSource {
				t.Fatalf("profile source = %q, want %q", result.ProfileSource, test.wantSource)
			}
			if finding := findingForType(t, result, "assume-role"); finding.State != StateSelected {
				t.Fatalf("finding = %#v", finding)
			}
		})
	}
}

func TestAnalyzeRejectsUnsupportedAssumeRoleConfigurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configBody string
		wantError  error
	}{
		{name: "missing source_profile", configBody: "[profile example]\nrole_arn = example-role\n", wantError: ErrInvalidAssumeRoleConfiguration},
		{name: "missing role_arn", configBody: "[profile example]\nsource_profile = source\n" + staticConfig("source"), wantError: ErrInvalidAssumeRoleConfiguration},
		{name: "missing source definition", configBody: roleConfig("missing"), wantError: ErrInvalidAssumeRoleConfiguration},
		{name: "self cycle", configBody: roleConfig("example"), wantError: ErrUnsupportedAssumeRoleChain},
		{name: "multi-profile cycle", configBody: roleConfig("source") + "[profile source]\nrole_arn = nested-role\nsource_profile = example\n", wantError: ErrUnsupportedAssumeRoleChain},
		{name: "nested role", configBody: roleConfig("source") + "[profile source]\nrole_arn = nested-role\nsource_profile = base\n" + staticConfig("base"), wantError: ErrUnsupportedAssumeRoleChain},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configPath, credentialsPath := writeSharedFiles(t, test.configBody, "")
			_, err := Analyze(context.Background(), Options{
				Environment:     map[string]string{"AWS_PROFILE": "example"},
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestAnalyzeDoesNotResolveUnsupportedAssumeRoleSources(t *testing.T) {
	t.Parallel()

	configPath, credentialsPath := writeSharedFiles(t,
		roleConfig("source")+"[profile source]\ncredential_process = must-not-run\n", "")
	result, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "example"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedProvider)
	}
	finding := findingForSource(t, result, "shared-config")
	if finding.Type != "source-profile-credential-process" || finding.State != StateIgnored {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestAnalyzeRejectsDeferredAssumeRoleOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configBody string
		wantType   string
	}{
		{
			name:       "credential_source",
			configBody: "[profile example]\nrole_arn = example-role\ncredential_source = Ec2InstanceMetadata\n",
			wantType:   "credential-source",
		},
		{
			name:       "MFA prompting",
			configBody: roleConfig("source") + "mfa_serial = example-mfa\n" + staticConfig("source"),
			wantType:   "assume-role-mfa",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configPath, credentialsPath := writeSharedFiles(t, test.configBody, "")
			result, err := Analyze(context.Background(), Options{
				Environment:     map[string]string{"AWS_PROFILE": "example"},
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if !errors.Is(err, ErrUnsupportedProvider) {
				t.Fatalf("error = %v, want %v", err, ErrUnsupportedProvider)
			}
			finding := findingForSource(t, result, "shared-config")
			if finding.Type != test.wantType || finding.State != StateIgnored {
				t.Fatalf("finding = %#v", finding)
			}
		})
	}
}

func TestEnvironmentCredentialsShadowAssumeRole(t *testing.T) {
	t.Parallel()

	configPath, credentialsPath := writeSharedFiles(t, roleConfig("missing"), "")
	result, err := Analyze(context.Background(), Options{
		Environment:     completeEnvironment("example"),
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if finding := findingForType(t, result, "assume-role"); finding.State != StateShadowed {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestSharedCredentialsShadowAssumeRole(t *testing.T) {
	t.Parallel()

	configPath, credentialsPath := writeSharedFiles(t, roleConfig("source"), staticCredentials("example"))
	result, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "example"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if finding := findingForSource(t, result, "shared-credentials"); finding.State != StateSelected {
		t.Fatalf("credentials finding = %#v", finding)
	}
	if finding := findingForType(t, result, "assume-role"); finding.State != StateShadowed {
		t.Fatalf("role finding = %#v", finding)
	}
}

func TestAnalyzeSelectsSSOProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		explicitProfile string
		environment     map[string]string
		configBody      string
		wantReason      string
	}{
		{
			name:        "modern SSO",
			environment: map[string]string{"AWS_PROFILE": "example"},
			configBody: "[profile example]\nsso_session = example-session\nsso_account_id = 000000000000\nsso_role_name = ExampleRole\n" +
				"[sso-session example-session]\nsso_start_url = https://example.invalid/start\nsso_region = example-region\n",
			wantReason: "modern SSO profile selected",
		},
		{
			name:            "legacy SSO with explicit profile",
			explicitProfile: "example",
			environment:     completeEnvironment("other"),
			configBody:      legacySSOConfig("example"),
			wantReason:      "legacy SSO profile selected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configPath, credentialsPath := writeSharedFiles(t, test.configBody, "")
			result, err := Analyze(context.Background(), Options{
				ExplicitProfile: test.explicitProfile,
				Environment:     test.environment,
				ConfigPath:      configPath,
				CredentialsPath: credentialsPath,
			})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			finding := findingForType(t, result, "sso")
			if finding.State != StateSelected || finding.Reason != test.wantReason {
				t.Fatalf("finding = %#v", finding)
			}
		})
	}
}

func TestStaticCredentialsShadowSSO(t *testing.T) {
	t.Parallel()

	configPath, credentialsPath := writeSharedFiles(t, legacySSOConfig("example"), staticCredentials("example"))
	result, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "example"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if finding := findingForSource(t, result, "shared-credentials"); finding.State != StateSelected {
		t.Fatalf("static finding = %#v", finding)
	}
	if finding := findingForType(t, result, "sso"); finding.State != StateShadowed {
		t.Fatalf("SSO finding = %#v", finding)
	}
}

func TestSSOProfileRequiresAccountAndRole(t *testing.T) {
	t.Parallel()

	configBody := "[profile example]\nsso_session = example-session\n" +
		"[sso-session example-session]\nsso_start_url = https://example.invalid/start\nsso_region = example-region\n"
	configPath, credentialsPath := writeSharedFiles(t, configBody, "")
	_, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "example"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if !errors.Is(err, ErrInvalidSSOConfiguration) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidSSOConfiguration)
	}
}

func TestFormatDoesNotExposeValues(t *testing.T) {
	t.Parallel()

	configPath, credentialsPath := writeSharedFiles(t, "", staticCredentials("private-profile"))
	result, err := Analyze(context.Background(), Options{
		Environment:     map[string]string{"AWS_PROFILE": "private-profile"},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	output := Format(result)
	for _, forbidden := range []string{"private-profile", "example-access-key", "example-secret-key", "example-session-token"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains forbidden value %q: %s", forbidden, output)
		}
	}
}

func TestAssumeRoleFormatDoesNotExposeConfigurationValues(t *testing.T) {
	t.Parallel()

	config := "[profile private-role]\nrole_arn = private-role-arn\nsource_profile = private-source\nexternal_id = private-external-id\n" +
		"[profile private-source]\naws_access_key_id = example-access-key\naws_secret_access_key = example-secret-key\n"
	configPath, credentialsPath := writeSharedFiles(t, config, "")
	result, err := Analyze(context.Background(), Options{
		ExplicitProfile: "private-role",
		Environment:     map[string]string{},
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	output := Format(result)
	for _, forbidden := range []string{
		"private-role", "private-source", "private-role-arn", "private-external-id",
		"example-access-key", "example-secret-key",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains forbidden value %q: %s", forbidden, output)
		}
	}
}

func writeSharedFiles(t *testing.T, configBody, credentialsBody string) (string, string) {
	t.Helper()

	root := filepath.Join(t.TempDir(), "path with spaces", ".aws")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create test directory: %v", err)
	}

	configPath := filepath.Join(root, "config")
	if configBody != "" {
		if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	credentialsPath := filepath.Join(root, "credentials")
	if credentialsBody != "" {
		if err := os.WriteFile(credentialsPath, []byte(credentialsBody), 0o600); err != nil {
			t.Fatalf("write credentials: %v", err)
		}
	}

	return configPath, credentialsPath
}

func completeEnvironment(profile string) map[string]string {
	return map[string]string{
		"AWS_PROFILE":           profile,
		"AWS_ACCESS_KEY_ID":     "example-access-key",
		"AWS_SECRET_ACCESS_KEY": "example-secret-key",
		"AWS_SESSION_TOKEN":     "example-session-token",
	}
}

func staticConfig(profile string) string {
	return "[profile " + profile + "]\naws_access_key_id = example-access-key\naws_secret_access_key = example-secret-key\n"
}

func staticCredentials(profile string) string {
	return "[" + profile + "]\naws_access_key_id = example-access-key\naws_secret_access_key = example-secret-key\naws_session_token = example-session-token\n"
}

func legacySSOConfig(profile string) string {
	return "[profile " + profile + "]\n" +
		"sso_start_url = https://example.invalid/start\n" +
		"sso_region = example-region\n" +
		"sso_account_id = 000000000000\n" +
		"sso_role_name = ExampleRole\n"
}

func roleConfig(sourceProfile string) string {
	return "[profile example]\nrole_arn = example-role\nsource_profile = " + sourceProfile + "\n"
}

func findingForSource(t *testing.T, result Result, source string) Finding {
	t.Helper()

	for _, finding := range result.Findings {
		if finding.Source == source {
			return finding
		}
	}
	t.Fatalf("finding for source %q not found", source)
	return Finding{}
}

func findingForType(t *testing.T, result Result, findingType string) Finding {
	t.Helper()

	for _, finding := range result.Findings {
		if finding.Type == findingType {
			return finding
		}
	}
	t.Fatalf("finding for type %q not found", findingType)
	return Finding{}
}
