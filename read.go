package sdfinder

import (
	"bufio"
	"io"
	"strings"
)

type Reader interface {
	Get() (string, error)
	Error() error
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
	return "", io.EOF
}

func (fr FileReader) Error() error {
	return fr.scanner.Err()
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

func (sr StrReader) Error() error {
	return nil
}

func Read(reader Reader, f func(line string), postFunc func()) error {
	for {
		line, readErr := reader.Get()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if len(line) == 0 && readErr == io.EOF {
			break
		}
		f(line)
		if readErr == io.EOF {
			break
		}
	}
	if err := reader.Error(); err != nil {
		return err
	}
	postFunc()
	return nil
}
