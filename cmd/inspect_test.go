package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k-taketani-job/aws-cred-trace/internal/analyze"
	"github.com/k-taketani-job/aws-cred-trace/internal/identity"
)

func TestInspectSkipsSTS(t *testing.T) {
	root := t.TempDir()
	credentialsPath := filepath.Join(root, "credentials")
	if err := os.WriteFile(credentialsPath, []byte("[default]\naws_access_key_id = example-access-key\naws_secret_access_key = example-secret-key\n"), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(root, "missing-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")

	called := false
	command := newInspectCommandWithVerifier(func(context.Context, analyze.Options, analyze.Result) (identity.Result, error) {
		called = true
		return identity.Result{}, errors.New("must not be called")
	})
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--no-sts"})

	if err := command.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if called {
		t.Fatal("STS verifier was called")
	}
	if !strings.Contains(output.String(), "IDENTITY_VERIFICATION\nSTATUS   skipped") {
		t.Fatalf("output does not show skipped verification: %s", output.String())
	}
}

func TestInspectNoSTSSkipsAllSSOCredentialActivity(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config")
	config := "[profile example]\n" +
		"sso_session = example-session\n" +
		"sso_account_id = 000000000000\n" +
		"sso_role_name = ExampleRole\n" +
		"[sso-session example-session]\n" +
		"sso_start_url = https://example.invalid/start\n" +
		"sso_region = example-region\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(root, "missing-credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "example")
	t.Setenv("AWS_DEFAULT_PROFILE", "")

	called := false
	command := newInspectCommandWithVerifier(func(context.Context, analyze.Options, analyze.Result) (identity.Result, error) {
		called = true
		return identity.Result{}, errors.New("must not be called")
	})
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--no-sts"})

	if err := command.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if called {
		t.Fatal("credential construction or STS verifier was called")
	}
	for _, expected := range []string{"selected  shared-config", "sso", "STATUS   skipped"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output does not contain %q: %s", expected, output.String())
		}
	}
}

func TestInspectPreservesAnalysisOnSTSFailure(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(root, "missing-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(root, "missing-credentials"))
	t.Setenv("AWS_ACCESS_KEY_ID", "example-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example-secret-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")

	command := newInspectCommandWithVerifier(func(context.Context, analyze.Options, analyze.Result) (identity.Result, error) {
		return identity.Result{Status: "unverified", Reason: identity.ErrNetwork.Error()}, identity.ErrNetwork
	})
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)

	err := command.Execute()
	if !errors.Is(err, identity.ErrNetwork) {
		t.Fatalf("error = %v, want %v", err, identity.ErrNetwork)
	}
	for _, expected := range []string{"CREDENTIAL", "selected  environment", "IDENTITY_VERIFICATION", "STATUS   unverified"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output does not contain %q: %s", expected, output.String())
		}
	}
}
