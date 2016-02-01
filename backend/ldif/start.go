package ldif

import (
	"fmt"
	"io/ioutil"
)

func (l *LdifBackend) Start() error {
	files, _ := ioutil.ReadDir(l.Path)
	for _, f := range files {
		if err := l.readLdif(fmt.Sprintf("%s/%s", l.Path, f.Name())); err != nil {
			return err
		}
	}
	return nil
}
