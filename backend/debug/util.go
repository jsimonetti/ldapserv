package debug

import "github.com/davecgh/go-spew/spew"

func dump(m interface{}) {
	spew.Dump(m)
}
