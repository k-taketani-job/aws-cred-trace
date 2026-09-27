package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// State describes how a credential source participates in selection.
type State string

const (
	StateSelected State = "selected"
	StateShadowed State = "shadowed"
	StateIgnored  State = "ignored"
)

var (
	// ErrNoCredentials indicates that no supported credential source was found.
	ErrNoCredentials = errors.New("no supported credentials found")
	// ErrUnsupportedProvider indicates that resolving credentials would require an unsupported provider.
	ErrUnsupportedProvider = errors.New("credential resolution requires an unsupported provider")
	// ErrProfileNotFound indicates that a selected named profile is absent from both shared files.
	ErrProfileNotFound = errors.New("selected profile was not found")
	// ErrInvalidSSOConfiguration indicates that the selected SSO profile cannot provide AWS credentials.
	ErrInvalidSSOConfiguration = errors.New("selected SSO profile is incomplete or invalid")
	// ErrInvalidAssumeRoleConfiguration indicates that a role profile or its source_profile is incomplete.
	ErrInvalidAssumeRoleConfiguration = errors.New("selected AssumeRole profile is incomplete or invalid")
	// ErrUnsupportedAssumeRoleChain indicates that the selected profile requires more than one role hop.
	ErrUnsupportedAssumeRoleChain = errors.New("nested or cyclic AssumeRole chains are unsupported")
)

// Finding is a value-free explanation of one credential source.
type Finding struct {
	State  State
	Source string
	Type   string
	Reason string
}

// Result contains profile-selection metadata and value-free credential findings.
type Result struct {
	Profile       string
	ProfileSource string
	Region        string
	Findings      []Finding
}

// Options provides inputs to credential analysis.
type Options struct {
	ExplicitProfile string
	Environment     map[string]string
	ConfigPath      string
	CredentialsPath string
	Region          string
}

// OptionsFromEnvironment builds analysis options using AWS SDK path defaults.
func OptionsFromEnvironment(explicitProfile string) Options {
	environment := map[string]string{}
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_PROFILE",
		"AWS_DEFAULT_PROFILE",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
	} {
		environment[name] = os.Getenv(name)
	}

	configPath := os.Getenv("AWS_CONFIG_FILE")
	if configPath == "" {
		configPath = awsconfig.DefaultSharedConfigFilename()
	}

	credentialsPath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credentialsPath == "" {
		credentialsPath = awsconfig.DefaultSharedCredentialsFilename()
	}

	return Options{
		ExplicitProfile: explicitProfile,
		Environment:     environment,
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
		Region:          selectRegion(environment),
	}
}

func selectRegion(environment map[string]string) string {
	if region := environment["AWS_REGION"]; region != "" {
		return region
	}
	return environment["AWS_DEFAULT_REGION"]
}

// Analyze determines supported credential-source precedence without retrieving credentials.
func Analyze(ctx context.Context, options Options) (Result, error) {
	profile, profileSource := selectProfile(options)
	result := Result{Profile: profile, ProfileSource: profileSource}

	environmentFinding, environmentSelected := analyzeEnvironment(options)
	result.Findings = append(result.Findings, environmentFinding)

	credentials, err := loadSharedFile(ctx, options.CredentialsPath, profile, false)
	if err != nil {
		result.Findings = append(result.Findings, invalidFileFinding("shared-credentials"))
		return result, err
	}
	credentialsFinding, credentialsSelected := staticFinding(
		"shared-credentials",
		credentials,
		environmentSelected,
		"environment credentials take precedence",
	)

	sharedConfig, err := loadConfigFile(ctx, options, profile, environmentSelected || credentialsSelected)
	if err != nil {
		result.Findings = append(result.Findings, invalidFileFinding("shared-config"))
		return result, err
	}
	result.Region = options.Region
	if result.Region == "" {
		result.Region = sharedConfig.region
	}

	result.Findings = append(result.Findings, credentialsFinding)

	configFindings, configSelected := configFileFindings(sharedConfig, environmentSelected, credentialsSelected)
	result.Findings = append(result.Findings, configFindings...)

	if environmentSelected || credentialsSelected || configSelected {
		return result, nil
	}
	if sharedConfig.unsupported != "" {
		return result, ErrUnsupportedProvider
	}
	if profileSource != "default" && !credentials.profile && !sharedConfig.profile {
		return result, ErrProfileNotFound
	}

	return result, ErrNoCredentials
}

func selectProfile(options Options) (string, string) {
	if options.ExplicitProfile != "" {
		return options.ExplicitProfile, "--profile"
	}
	if profile := options.Environment["AWS_PROFILE"]; profile != "" {
		return profile, "AWS_PROFILE"
	}
	if profile := options.Environment["AWS_DEFAULT_PROFILE"]; profile != "" {
		return profile, "AWS_DEFAULT_PROFILE"
	}
	return awsconfig.DefaultSharedConfigProfile, "default"
}

func analyzeEnvironment(options Options) (Finding, bool) {
	hasAccessKey := options.Environment["AWS_ACCESS_KEY_ID"] != ""
	hasSecretKey := options.Environment["AWS_SECRET_ACCESS_KEY"] != ""
	hasSessionToken := options.Environment["AWS_SESSION_TOKEN"] != ""

	if !hasAccessKey && !hasSecretKey && !hasSessionToken {
		return Finding{State: StateIgnored, Source: "environment", Type: "static", Reason: "credential variables are not set"}, false
	}
	if !hasAccessKey || !hasSecretKey {
		return Finding{State: StateIgnored, Source: "environment", Type: "static", Reason: "incomplete static credential pair"}, false
	}
	if options.ExplicitProfile != "" {
		return Finding{State: StateIgnored, Source: "environment", Type: "static", Reason: "explicit --profile takes precedence"}, false
	}

	return Finding{State: StateSelected, Source: "environment", Type: "static", Reason: "complete static credential pair"}, true
}

type fileCandidate struct {
	exists      bool
	profile     bool
	static      bool
	sso         bool
	ssoMode     string
	assumeRole  bool
	roleSource  string
	roleType    string
	roleMode    string
	unsupported string
	region      string
}

func loadConfigFile(ctx context.Context, options Options, profile string, higherSelected bool) (fileCandidate, error) {
	_, err := os.Stat(options.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return fileCandidate{}, nil
	}
	if err != nil {
		return fileCandidate{}, errors.New("shared AWS file cannot be read")
	}

	var shared awsconfig.SharedConfig
	if higherSelected {
		shared, err = loadSharedConfig(ctx, options.ConfigPath, profile, true)
	} else {
		shared, err = loadMergedConfig(ctx, options, profile)
	}
	if err != nil {
		var assumeRoleError awsconfig.SharedConfigAssumeRoleError
		if errors.As(err, &assumeRoleError) {
			candidate := fileCandidate{exists: true, profile: true, assumeRole: true}
			if higherSelected {
				return candidate, nil
			}
			if assumeRoleError.Profile == profile {
				return candidate, ErrUnsupportedAssumeRoleChain
			}
			return candidate, ErrInvalidAssumeRoleConfiguration
		}
		var requiresARN awsconfig.CredentialRequiresARNError
		if errors.As(err, &requiresARN) {
			return fileCandidate{exists: true, profile: true, assumeRole: true}, ErrInvalidAssumeRoleConfiguration
		}
		var profileNotFound awsconfig.SharedConfigProfileNotExistError
		if errors.As(err, &profileNotFound) {
			return fileCandidate{exists: true}, nil
		}
		return fileCandidate{}, errors.New("shared AWS file is invalid for the selected profile")
	}

	candidate := fileCandidate{
		exists:  true,
		profile: true,
		static:  shared.Credentials.HasKeys(),
		region:  shared.Region,
	}
	candidate.sso, candidate.ssoMode = ssoType(shared)
	if candidate.sso && (shared.SSOAccountID == "" || shared.SSORoleName == "") {
		return candidate, ErrInvalidSSOConfiguration
	}
	candidate.unsupported = unsupportedType(shared)
	if shared.RoleARN == "" && shared.SourceProfileName == "" {
		return candidate, nil
	}
	if candidate.unsupported != "" {
		return candidate, nil
	}

	candidate.assumeRole = true
	candidate.unsupported = ""
	if shared.RoleARN == "" || shared.SourceProfileName == "" || shared.Source == nil {
		return candidate, ErrInvalidAssumeRoleConfiguration
	}
	if shared.MFASerial != "" {
		candidate.unsupported = "assume-role-mfa"
		return candidate, nil
	}
	if shared.Source.RoleARN != "" || shared.Source.SourceProfileName != "" {
		return candidate, ErrUnsupportedAssumeRoleChain
	}
	if sourceUnsupported := unsupportedType(*shared.Source); sourceUnsupported != "" {
		candidate.unsupported = "source-profile-" + sourceUnsupported
		return candidate, nil
	}

	if shared.Source.Credentials.HasKeys() {
		candidate.roleSource = staticSource(ctx, options, shared.SourceProfileName)
		candidate.roleType = "static"
		return candidate, nil
	}
	if sourceSSO, mode := ssoType(*shared.Source); sourceSSO {
		if shared.Source.SSOAccountID == "" || shared.Source.SSORoleName == "" {
			return candidate, ErrInvalidSSOConfiguration
		}
		candidate.roleSource = "shared-config"
		candidate.roleType = "sso"
		candidate.roleMode = mode
		return candidate, nil
	}
	return candidate, ErrInvalidAssumeRoleConfiguration
}

func loadMergedConfig(ctx context.Context, options Options, profile string) (awsconfig.SharedConfig, error) {
	return awsconfig.LoadSharedConfigProfile(ctx, profile, func(loadOptions *awsconfig.LoadSharedConfigOptions) {
		loadOptions.ConfigFiles = []string{options.ConfigPath}
		loadOptions.CredentialsFiles = []string{options.CredentialsPath}
	})
}

func staticSource(ctx context.Context, options Options, profile string) string {
	shared, err := loadSharedConfig(ctx, options.CredentialsPath, profile, false)
	if err == nil && shared.Credentials.HasKeys() {
		return "shared-credentials"
	}
	return "shared-config"
}

func loadSharedFile(ctx context.Context, path, profile string, configFile bool) (fileCandidate, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileCandidate{}, nil
	}
	if err != nil {
		return fileCandidate{}, errors.New("shared AWS file cannot be read")
	}

	shared, err := loadSharedConfig(ctx, path, profile, configFile)
	if err != nil {
		var profileNotFound awsconfig.SharedConfigProfileNotExistError
		if errors.As(err, &profileNotFound) {
			return fileCandidate{exists: true}, nil
		}
		var assumeRoleError awsconfig.SharedConfigAssumeRoleError
		if configFile && errors.As(err, &assumeRoleError) {
			return fileCandidate{exists: true, profile: true, unsupported: "assume-role"}, nil
		}
		return fileCandidate{}, errors.New("shared AWS file is invalid for the selected profile")
	}

	candidate := fileCandidate{
		exists:  true,
		profile: true,
		static:  shared.Credentials.HasKeys(),
		region:  shared.Region,
	}
	if configFile {
		candidate.sso, candidate.ssoMode = ssoType(shared)
		if candidate.sso && (shared.SSOAccountID == "" || shared.SSORoleName == "") {
			return candidate, ErrInvalidSSOConfiguration
		}
		candidate.unsupported = unsupportedType(shared)
	}
	return candidate, nil
}

func loadSharedConfig(ctx context.Context, path, profile string, configFile bool) (awsconfig.SharedConfig, error) {
	return awsconfig.LoadSharedConfigProfile(ctx, profile, func(options *awsconfig.LoadSharedConfigOptions) {
		if configFile {
			options.ConfigFiles = []string{path}
			options.CredentialsFiles = []string{}
			return
		}
		options.ConfigFiles = []string{}
		options.CredentialsFiles = []string{path}
	})
}

func unsupportedType(shared awsconfig.SharedConfig) string {
	switch {
	case shared.CredentialProcess != "":
		return "credential-process"
	case shared.CredentialSource != "":
		return "credential-source"
	case shared.WebIdentityTokenFile != "":
		return "web-identity"
	default:
		return ""
	}
}

func ssoType(shared awsconfig.SharedConfig) (bool, string) {
	if shared.SSOSession != nil || shared.SSOSessionName != "" {
		return true, "modern"
	}
	if shared.SSOStartURL != "" || shared.SSORegion != "" || shared.SSOAccountID != "" || shared.SSORoleName != "" {
		return true, "legacy"
	}
	return false, ""
}

func staticFinding(source string, candidate fileCandidate, higherSelected bool, shadowReason string) (Finding, bool) {
	if !candidate.exists {
		return Finding{State: StateIgnored, Source: source, Type: "static", Reason: "file not found"}, false
	}
	if !candidate.profile {
		return Finding{State: StateIgnored, Source: source, Type: "static", Reason: "selected profile not found"}, false
	}
	if !candidate.static {
		return Finding{State: StateIgnored, Source: source, Type: "static", Reason: "no supported static credentials"}, false
	}
	if higherSelected {
		return Finding{State: StateShadowed, Source: source, Type: "static", Reason: shadowReason}, false
	}
	return Finding{State: StateSelected, Source: source, Type: "static", Reason: "complete static credential pair"}, true
}

func configFileFindings(candidate fileCandidate, environmentSelected, credentialsSelected bool) ([]Finding, bool) {
	higherSelected := environmentSelected || credentialsSelected
	reason := "shared credentials file takes precedence"
	if environmentSelected {
		reason = "environment credentials take precedence"
	}
	if candidate.assumeRole {
		if higherSelected {
			return []Finding{{
				State:  StateShadowed,
				Source: "shared-config",
				Type:   "assume-role",
				Reason: reason,
			}}, false
		}
		if candidate.unsupported != "" {
			return []Finding{{
				State:  StateIgnored,
				Source: "shared-config",
				Type:   candidate.unsupported,
				Reason: "unsupported; not executed",
			}}, false
		}
		roleReason := "role_arn with direct source_profile selected"
		sourceReason := "source_profile resolves via " + candidate.roleSource
		if candidate.roleType == "sso" {
			sourceReason = candidate.roleMode + " SSO source_profile selected"
		}
		return []Finding{
			{State: StateSelected, Source: "shared-config", Type: "assume-role", Reason: roleReason},
			{State: StateSelected, Source: "source-profile", Type: candidate.roleType, Reason: sourceReason},
		}, true
	}

	if candidate.unsupported != "" && !candidate.static {
		return []Finding{{
			State:  StateIgnored,
			Source: "shared-config",
			Type:   candidate.unsupported,
			Reason: unsupportedReason(environmentSelected || credentialsSelected),
		}}, false
	}

	staticResult, staticSelected := staticFinding("shared-config", candidate, higherSelected, reason)
	if !candidate.sso {
		return []Finding{staticResult}, staticSelected
	}

	ssoState := StateSelected
	ssoReason := candidate.ssoMode + " SSO profile selected"
	if higherSelected {
		ssoState = StateShadowed
		ssoReason = reason
	} else if staticSelected {
		ssoState = StateShadowed
		ssoReason = "static credentials in the selected profile take precedence"
	}
	ssoFinding := Finding{State: ssoState, Source: "shared-config", Type: "sso", Reason: ssoReason}
	if candidate.static {
		return []Finding{staticResult, ssoFinding}, staticSelected
	}
	return []Finding{ssoFinding}, ssoState == StateSelected
}

func unsupportedReason(higherSelected bool) string {
	if higherSelected {
		return "not evaluated because a supported higher-precedence source is selected"
	}
	return "unsupported in v0.2; not executed"
}

func invalidFileFinding(source string) Finding {
	return Finding{State: StateIgnored, Source: source, Type: "static", Reason: "invalid or unreadable shared AWS file"}
}

// Format renders findings without credential values or selected profile names.
func Format(result Result) string {
	var output strings.Builder
	fmt.Fprintln(&output, "CREDENTIAL_SOURCE_ANALYSIS")
	fmt.Fprintf(&output, "PROFILE_SOURCE  %s\n", result.ProfileSource)
	fmt.Fprintln(&output, "STATUS    SOURCE              TYPE                 REASON")
	for _, finding := range result.Findings {
		fmt.Fprintf(
			&output,
			"%-9s %-19s %-20s %s\n",
			finding.State,
			finding.Source,
			finding.Type,
			finding.Reason,
		)
	}
	return output.String()
}
