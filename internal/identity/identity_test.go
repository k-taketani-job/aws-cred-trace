package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/k-taketani-job/aws-cred-trace/internal/credentials"
)

type fakeCaller struct {
	output *sts.GetCallerIdentityOutput
	err    error
	calls  int
}

func (client *fakeCaller) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	client.calls++
	return client.output, client.err
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		output     *sts.GetCallerIdentityOutput
		err        error
		wantStatus string
		wantError  error
	}{
		{
			name:       "success",
			output:     &sts.GetCallerIdentityOutput{Account: aws.String("example-account"), Arn: aws.String("example-arn")},
			wantStatus: "verified",
		},
		{name: "expired credentials", err: &smithy.GenericAPIError{Code: "ExpiredToken", Message: "sensitive detail"}, wantStatus: "unverified", wantError: ErrExpired},
		{name: "invalid credentials", err: &smithy.GenericAPIError{Code: "InvalidClientTokenId", Message: "sensitive detail"}, wantStatus: "unverified", wantError: ErrInvalid},
		{name: "unauthorized", err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "sensitive detail"}, wantStatus: "unverified", wantError: ErrUnauthorized},
		{name: "network failure", err: fakeNetworkError{}, wantStatus: "unverified", wantError: ErrNetwork},
		{name: "SSO session unavailable", err: credentials.ErrSSOSessionUnavailable, wantStatus: "unverified", wantError: ErrSSOSession},
		{name: "other service error", err: &smithy.GenericAPIError{Code: "ExampleFailure", Message: "sensitive detail"}, wantStatus: "unverified", wantError: ErrVerification},
		{name: "missing response fields", output: &sts.GetCallerIdentityOutput{}, wantStatus: "unverified", wantError: ErrVerification},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &fakeCaller{output: test.output, err: test.err}
			result, err := Verify(context.Background(), client)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if result.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q", result.Status, test.wantStatus)
			}
			if client.calls != 1 {
				t.Fatalf("calls = %d, want 1", client.calls)
			}
			if strings.Contains(result.Reason, "sensitive detail") {
				t.Fatalf("reason exposes service detail: %q", result.Reason)
			}
		})
	}
}

type fakeNetworkError struct{}

func (fakeNetworkError) Error() string   { return "sensitive network detail" }
func (fakeNetworkError) Timeout() bool   { return true }
func (fakeNetworkError) Temporary() bool { return true }

func TestFormatIncludesOnlyApprovedIdentityFields(t *testing.T) {
	t.Parallel()

	output := Format(Result{Status: "verified", Account: "example-account", ARN: "example-arn"})
	for _, expected := range []string{"IDENTITY_VERIFICATION", "example-account", "example-arn"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output does not contain %q: %s", expected, output)
		}
	}
	for _, forbidden := range []string{"access key", "secret key", "session token"} {
		if strings.Contains(strings.ToLower(output), forbidden) {
			t.Fatalf("output contains forbidden field %q: %s", forbidden, output)
		}
	}
}

func TestFormatDoesNotRepeatVerificationError(t *testing.T) {
	t.Parallel()

	output := Format(Result{Status: "unverified", Reason: ErrInvalid.Error()})
	if strings.Contains(output, ErrInvalid.Error()) {
		t.Fatalf("output repeats the verification error: %s", output)
	}
}
