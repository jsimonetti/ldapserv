package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func readLdifs() error {
	files, _ := ioutil.ReadDir("./ldif/")
	for _, f := range files {
		if err := readLdif(fmt.Sprintf("./ldif/%s", f.Name())); err != nil {
			return err
		}
	}
	return nil
}

type ldif struct {
	dn   string
	attr []attr
}

type attr struct {
	name    string
	content string
}

var ldifs []ldif

func readLdif(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	dn := ""

	scanner := bufio.NewScanner(file)

	attrs := make([]attr, 0)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "dn" {
			if dn != "" {
				ldifs = append(ldifs, ldif{dn, attrs})
			}
			attrs = make([]attr, 0)
			dn = strings.TrimSpace(parts[1])
		} else {
			attrs = append(attrs, attr{parts[0], strings.TrimSpace(parts[1])})
		}
	}
	ldifs = append(ldifs, ldif{dn, attrs})

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
