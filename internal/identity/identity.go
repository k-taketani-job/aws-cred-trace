// Package identity verifies the effective caller without exposing credentials.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/k-taketani-job/aws-cred-trace/internal/credentials"
)

var (
	// ErrExpired indicates that STS rejected expired credentials.
	ErrExpired = errors.New("STS verification failed: credentials are expired")
	// ErrInvalid indicates that STS rejected invalid credentials.
	ErrInvalid = errors.New("STS verification failed: credentials are invalid")
	// ErrUnauthorized indicates that STS rejected the request as unauthorized.
	ErrUnauthorized = errors.New("STS verification failed: request is unauthorized")
	// ErrNetwork indicates that STS could not be reached.
	ErrNetwork = errors.New("STS verification failed: network request failed")
	// ErrSSOSession indicates that the selected cached SSO session cannot provide credentials.
	ErrSSOSession = errors.New("STS verification failed: SSO session is unavailable; run aws sso login explicitly")
	// ErrVerification indicates another sanitized STS failure.
	ErrVerification = errors.New("STS verification failed")
)

// Caller is the subset of the STS client used for identity verification.
type Caller interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Result contains only identity information approved for display.
type Result struct {
	Status  string
	Account string
	ARN     string
	Reason  string
}

// Verify calls STS once and converts failures to safe error categories.
func Verify(ctx context.Context, client Caller) (Result, error) {
	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		safeErr := classifyError(err)
		return Result{Status: "unverified", Reason: safeErr.Error()}, safeErr
	}
	if output == nil || output.Account == nil || output.Arn == nil {
		return Result{Status: "unverified", Reason: ErrVerification.Error()}, ErrVerification
	}
	return Result{Status: "verified", Account: *output.Account, ARN: *output.Arn}, nil
}

// Skipped returns the result used when network verification is disabled.
func Skipped() Result {
	return Result{Status: "skipped", Reason: "STS verification disabled"}
}

// Format renders identity status separately from credential-source analysis.
func Format(result Result) string {
	var output strings.Builder
	fmt.Fprintln(&output, "IDENTITY_VERIFICATION")
	fmt.Fprintf(&output, "STATUS   %s\n", result.Status)
	if result.Account != "" {
		fmt.Fprintf(&output, "ACCOUNT  %s\n", result.Account)
	}
	if result.ARN != "" {
		fmt.Fprintf(&output, "ARN      %s\n", result.ARN)
	}
	if result.Reason != "" && result.Status != "unverified" {
		fmt.Fprintf(&output, "REASON   %s\n", result.Reason)
	}
	return output.String()
}

func classifyError(err error) error {
	if errors.Is(err, credentials.ErrSSOSessionUnavailable) {
		return ErrSSOSession
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "ExpiredToken", "ExpiredTokenException", "RequestExpired":
			return ErrExpired
		case "InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException":
			return ErrInvalid
		case "AccessDenied", "AccessDeniedException", "Unauthorized", "UnauthorizedException":
			return ErrUnauthorized
		default:
			return ErrVerification
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, context.DeadlineExceeded) {
		return ErrNetwork
	}
	return ErrVerification
}
