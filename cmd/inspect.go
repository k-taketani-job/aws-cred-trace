package cmd

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/k-taketani-job/aws-cred-trace/internal/analyze"
	"github.com/k-taketani-job/aws-cred-trace/internal/credentials"
	"github.com/k-taketani-job/aws-cred-trace/internal/identity"
	"github.com/spf13/cobra"
)

func newInspectCommand() *cobra.Command {
	return newInspectCommandWithVerifier(verifyIdentity)
}

type identityVerifier func(context.Context, analyze.Options, analyze.Result) (identity.Result, error)

func newInspectCommandWithVerifier(verifier identityVerifier) *cobra.Command {
	var profile string
	var noSTS bool

	command := &cobra.Command{
		Use:   "inspect",
		Short: "Explain local AWS credential source selection",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			options := analyze.OptionsFromEnvironment(profile)
			result, err := analyze.Analyze(command.Context(), options)
			if _, writeErr := fmt.Fprint(command.OutOrStdout(), analyze.Format(result)); writeErr != nil {
				return fmt.Errorf("write output: %w", writeErr)
			}
			if err != nil {
				return err
			}

			verification := identity.Skipped()
			if !noSTS {
				verification, err = verifier(command.Context(), options, result)
			}
			if _, writeErr := fmt.Fprintf(command.OutOrStdout(), "\n%s", identity.Format(verification)); writeErr != nil {
				return fmt.Errorf("write output: %w", writeErr)
			}
			return err
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "Use a specific shared AWS profile")
	command.Flags().BoolVar(&noSTS, "no-sts", false, "Skip credential retrieval and all network verification")

	return command
}

func verifyIdentity(ctx context.Context, options analyze.Options, result analyze.Result) (identity.Result, error) {
	provider, err := credentials.Provider(ctx, options, result)
	if err != nil {
		return identity.Result{Status: "unverified", Reason: "selected credentials are unavailable"}, err
	}
	config := aws.Config{
		Region:      result.Region,
		Credentials: provider,
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = 2
			})
		},
	}
	return identity.Verify(ctx, sts.NewFromConfig(config))
}
