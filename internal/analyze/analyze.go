package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
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
	ErrUnsupportedProvider = errors.New("credential resolution requires a provider unsupported in v0.1")
	// ErrProfileNotFound indicates that a selected named profile is absent from both shared files.
	ErrProfileNotFound = errors.New("selected profile was not found")
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

// CredentialProvider returns only the supported static provider selected by Analyze.
// It deliberately avoids the SDK default credential chain so unsupported providers
// and metadata endpoints cannot be invoked.
func CredentialProvider(ctx context.Context, options Options, result Result) (aws.CredentialsProvider, error) {
	selected := ""
	for _, finding := range result.Findings {
		if finding.State == StateSelected {
			selected = finding.Source
			break
		}
	}

	var credentials aws.Credentials
	switch selected {
	case "environment":
		credentials = aws.Credentials{
			AccessKeyID:     options.Environment["AWS_ACCESS_KEY_ID"],
			SecretAccessKey: options.Environment["AWS_SECRET_ACCESS_KEY"],
			SessionToken:    options.Environment["AWS_SESSION_TOKEN"],
			Source:          "environment",
		}
	case "shared-credentials":
		shared, err := loadSharedConfig(ctx, options.CredentialsPath, result.Profile, false)
		if err != nil {
			return nil, ErrNoCredentials
		}
		credentials = shared.Credentials
	case "shared-config":
		shared, err := loadSharedConfig(ctx, options.ConfigPath, result.Profile, true)
		if err != nil {
			return nil, ErrNoCredentials
		}
		credentials = shared.Credentials
	default:
		return nil, ErrNoCredentials
	}

	if !credentials.HasKeys() {
		return nil, ErrNoCredentials
	}
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return credentials, nil
	}), nil
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

	sharedConfig, err := loadSharedFile(ctx, options.ConfigPath, profile, true)
	if err != nil {
		result.Findings = append(result.Findings, invalidFileFinding("shared-config"))
		return result, err
	}
	result.Region = options.Region
	if result.Region == "" {
		result.Region = sharedConfig.region
	}

	credentialsFinding, credentialsSelected := staticFinding(
		"shared-credentials",
		credentials,
		environmentSelected,
		"environment credentials take precedence",
	)
	result.Findings = append(result.Findings, credentialsFinding)

	configFinding, configSelected := configFileFinding(sharedConfig, environmentSelected, credentialsSelected)
	result.Findings = append(result.Findings, configFinding)

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
	unsupported string
	region      string
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
	case shared.RoleARN != "" || shared.SourceProfileName != "" || shared.CredentialSource != "":
		return "assume-role"
	case shared.SSOSession != nil || shared.SSOSessionName != "" || shared.SSOStartURL != "" || shared.SSORegion != "":
		return "sso"
	case shared.WebIdentityTokenFile != "":
		return "web-identity"
	default:
		return ""
	}
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

func configFileFinding(candidate fileCandidate, environmentSelected, credentialsSelected bool) (Finding, bool) {
	if candidate.unsupported != "" && !candidate.static {
		return Finding{
			State:  StateIgnored,
			Source: "shared-config",
			Type:   candidate.unsupported,
			Reason: unsupportedReason(environmentSelected || credentialsSelected),
		}, false
	}

	higherSelected := environmentSelected || credentialsSelected
	reason := "shared credentials file takes precedence"
	if environmentSelected {
		reason = "environment credentials take precedence"
	}
	return staticFinding("shared-config", candidate, higherSelected, reason)
}

func unsupportedReason(higherSelected bool) string {
	if higherSelected {
		return "not evaluated because a supported higher-precedence source is selected"
	}
	return "unsupported in v0.1; not executed"
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
