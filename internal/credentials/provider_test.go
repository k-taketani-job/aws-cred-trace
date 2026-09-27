package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/k-taketani-job/aws-cred-trace/internal/analyze"
)

func TestProviderConstructsSDKSSOProvidersWithoutRetrieval(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "modern",
			config: "[profile example]\nsso_session = example-session\nsso_account_id = 000000000000\nsso_role_name = ExampleRole\n" +
				"[sso-session example-session]\nsso_start_url = https://example.invalid/start\nsso_region = example-region\n",
		},
		{
			name: "legacy",
			config: "[profile example]\nsso_start_url = https://example.invalid/start\nsso_region = example-region\n" +
				"sso_account_id = 000000000000\nsso_role_name = ExampleRole\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "config")
			if err := os.WriteFile(configPath, []byte(test.config), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			options := analyze.Options{
				Environment:     map[string]string{"AWS_PROFILE": "example"},
				ConfigPath:      configPath,
				CredentialsPath: filepath.Join(root, "missing-credentials"),
			}
			result, err := analyze.Analyze(context.Background(), options)
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if _, err := Provider(context.Background(), options, result); err != nil {
				t.Fatalf("provider: %v", err)
			}
		})
	}
}

type fakeProvider struct {
	credentials aws.Credentials
	err         error
	calls       int
}

func (provider *fakeProvider) Retrieve(context.Context) (aws.Credentials, error) {
	provider.calls++
	return provider.credentials, provider.err
}

func TestProviderConstructsSSOWithoutRetrievingCredentials(t *testing.T) {
	underlying := &fakeProvider{credentials: aws.Credentials{AccessKeyID: "example", SecretAccessKey: "example"}}
	loadCalls := 0
	provider, err := providerWithLoader(
		context.Background(),
		analyze.Options{ConfigPath: "config-path", CredentialsPath: "credentials-path"},
		selectedSSOResult(),
		func(_ context.Context, optionFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
			loadCalls++
			options := awsconfig.LoadOptions{}
			for _, option := range optionFns {
				if optionErr := option(&options); optionErr != nil {
					t.Fatalf("apply load option: %v", optionErr)
				}
			}
			if options.SharedConfigProfile != "example" {
				t.Fatalf("profile = %q", options.SharedConfigProfile)
			}
			if options.EC2IMDSClientEnableState != imds.ClientDisabled {
				t.Fatalf("IMDS state = %v, want disabled", options.EC2IMDSClientEnableState)
			}
			return aws.Config{Credentials: underlying}, nil
		},
	)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if loadCalls != 1 || underlying.calls != 0 {
		t.Fatalf("load calls = %d, retrieval calls = %d", loadCalls, underlying.calls)
	}

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if underlying.calls != 1 {
		t.Fatalf("retrieval calls = %d, want 1", underlying.calls)
	}
}

func TestSSOProviderSanitizesRetrievalFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "missing cached token", err: errors.New("example cached token path must not escape")},
		{name: "expired session", err: errors.New("example refresh token must not escape")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			underlying := &fakeProvider{err: test.err}
			provider, err := providerWithLoader(
				context.Background(),
				analyze.Options{},
				selectedSSOResult(),
				func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
					return aws.Config{Credentials: underlying}, nil
				},
			)
			if err != nil {
				t.Fatalf("provider: %v", err)
			}
			if _, err := provider.Retrieve(context.Background()); !errors.Is(err, ErrSSOSessionUnavailable) {
				t.Fatalf("error = %v, want %v", err, ErrSSOSessionUnavailable)
			}
		})
	}
}

func selectedSSOResult() analyze.Result {
	return analyze.Result{
		Profile: "example",
		Findings: []analyze.Finding{{
			State:  analyze.StateSelected,
			Source: "shared-config",
			Type:   "sso",
		}},
	}
}
