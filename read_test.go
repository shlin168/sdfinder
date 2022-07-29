package sdfinder

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStrReader(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("abc.com,google.com"))
	var reader Reader
	reader = NewStrReader(r, ',')

	var domains []string
	Read(reader, func(line string) {
		domains = append(domains, line)
	}, func() {
		domains = append(domains, "final")
	})
	assert.Equal(t, []string{"abc.com", "google.com", "final"}, domains)
}

func TestFileReader(t *testing.T) {
	tmpFile := "/tmp/sdfinder.txt"
	err := os.WriteFile(tmpFile, []byte(`abc.com
google.com
test.com`), 0644)
	require.NoError(t, err)
	defer os.Remove(tmpFile)

	f, err := os.OpenFile(tmpFile, os.O_RDONLY, 0644)
	require.NoError(t, err)
	defer f.Close()
	reader := NewFileReader(f)

	var lines []string
	err = Read(reader, func(line string) {
		lines = append(lines, line)
	}, func() {
		lines = append(lines, "final")
	})
	require.NoError(t, err)
	t.Log(lines)
	assert.Equal(t, 4, len(lines))
	assert.Equal(t, "final", lines[len(lines)-1])
}
