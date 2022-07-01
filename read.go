package sdfinder

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

type Reader interface {
	Get() (string, error)
}

type FileReader struct {
	scanner *bufio.Scanner
}

func NewFileReader(reader io.Reader) *FileReader {
	return &FileReader{scanner: bufio.NewScanner(reader)}
}

func (fr FileReader) Get() (string, error) {
	if fr.scanner.Scan() {
		return fr.scanner.Text(), nil
	}
	return "", errors.New("scan error")
}

type StrReader struct {
	reader *bufio.Reader
	sep    byte
}

func NewStrReader(reader *bufio.Reader, sep byte) *StrReader {
	return &StrReader{reader: reader, sep: sep}
}

func (sr StrReader) Get() (string, error) {
	item, err := sr.reader.ReadString(sr.sep)
	if err != nil && err != io.EOF {
		return "", err
	}
	item = strings.TrimRight(item, string(sr.sep))
	return item, err
}
