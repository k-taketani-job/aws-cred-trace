package cmd

import "github.com/spf13/cobra"

// NewRootCommand creates the root command for aws-cred-trace.
func NewRootCommand() *cobra.Command {
	command := &cobra.Command{
		Use:           "aws-cred-trace",
		Short:         "Explain which AWS credentials are selected and why",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(newInspectCommand())

	return command
}

// Execute runs the root command.
func Execute() error {
	return NewRootCommand().Execute()
}
