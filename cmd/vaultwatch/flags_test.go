package main

import (
	"flag"
	"os"
	"testing"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

func TestParseFlags_Default(t *testing.T) {
	resetFlags()
	os.Args = []string{"vaultwatch"}

	should := parseFlags()
	if !should {
		t.Error("expected parseFlags to return true with no flags")
	}
}

func TestParseFlags_Version(t *testing.T) {
	resetFlags()
	os.Args = []string{"vaultwatch", "-version"}

	should := parseFlags()
	if should {
		t.Error("expected parseFlags to return false with -version flag")
	}
}

func TestParseFlags_Help(t *testing.T) {
	resetFlags()
	os.Args = []string{"vaultwatch", "-help"}

	should := parseFlags()
	if should {
		t.Error("expected parseFlags to return false with -help flag")
	}
}

func TestVersion_NotEmpty(t *testing.T) {
	if version == "" {
		t.Error("version constant must not be empty")
	}
}
