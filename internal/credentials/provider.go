// Package credentials constructs only credential providers approved by analysis.
package credentials

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/k-taketani-job/aws-cred-trace/internal/analyze"
)

var (
	// ErrUnavailable indicates that the selected credential provider could not be constructed.
	ErrUnavailable = errors.New("selected credentials are unavailable")
	// ErrSSOSessionUnavailable indicates that AWS SDK for Go v2 could not use the cached SSO session.
	ErrSSOSessionUnavailable = errors.New("selected SSO session is unavailable; run aws sso login explicitly")
)

type defaultConfigLoader func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error)

// Provider constructs the selected provider without retrieving credentials.
func Provider(ctx context.Context, options analyze.Options, result analyze.Result) (aws.CredentialsProvider, error) {
	return providerWithLoader(ctx, options, result, awsconfig.LoadDefaultConfig)
}

func providerWithLoader(
	ctx context.Context,
	options analyze.Options,
	result analyze.Result,
	load defaultConfigLoader,
) (aws.CredentialsProvider, error) {
	selected, ok := selectedFinding(result)
	if !ok {
		return nil, ErrUnavailable
	}

	if selected.Type == "sso" {
		cfg, err := load(
			ctx,
			awsconfig.WithSharedConfigProfile(result.Profile),
			awsconfig.WithSharedConfigFiles([]string{options.ConfigPath}),
			awsconfig.WithSharedCredentialsFiles([]string{options.CredentialsPath}),
			awsconfig.WithEC2IMDSClientEnableState(imds.ClientDisabled),
		)
		if err != nil || cfg.Credentials == nil {
			return nil, ErrUnavailable
		}
		return safeSSOProvider{provider: cfg.Credentials}, nil
	}

	credentials, err := staticCredentials(ctx, options, result, selected.Source)
	if err != nil || !credentials.HasKeys() {
		return nil, ErrUnavailable
	}
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return credentials, nil
	}), nil
}

func selectedFinding(result analyze.Result) (analyze.Finding, bool) {
	for _, finding := range result.Findings {
		if finding.State == analyze.StateSelected {
			return finding, true
		}
	}
	return analyze.Finding{}, false
}

func staticCredentials(
	ctx context.Context,
	options analyze.Options,
	result analyze.Result,
	source string,
) (aws.Credentials, error) {
	switch source {
	case "environment":
		return aws.Credentials{
			AccessKeyID:     options.Environment["AWS_ACCESS_KEY_ID"],
			SecretAccessKey: options.Environment["AWS_SECRET_ACCESS_KEY"],
			SessionToken:    options.Environment["AWS_SESSION_TOKEN"],
			Source:          "environment",
		}, nil
	case "shared-credentials":
		shared, err := loadSharedConfig(ctx, options.CredentialsPath, result.Profile, false)
		return shared.Credentials, err
	case "shared-config":
		shared, err := loadSharedConfig(ctx, options.ConfigPath, result.Profile, true)
		return shared.Credentials, err
	default:
		return aws.Credentials{}, ErrUnavailable
	}
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

type safeSSOProvider struct {
	provider aws.CredentialsProvider
}

func (provider safeSSOProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	credentials, err := provider.provider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, ErrSSOSessionUnavailable
	}
	return credentials, nil
}
