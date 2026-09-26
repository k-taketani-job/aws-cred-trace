package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommandHelp(t *testing.T) {
	t.Parallel()

	command := NewRootCommand()
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("execute help: %v", err)
	}

	if !strings.Contains(output.String(), "Explain which AWS credentials are selected and why") {
		t.Fatalf("help output does not contain the command description: %q", output.String())
	}
}
