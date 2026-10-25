package evaluation

import (
	conf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/jcchavezs/mergefs"
	"io/fs"
	"testing"
)

func TestBundleEnumeration(t *testing.T) {
	root := mergefs.Merge(crs.FS, conf.FS)
	count := 0
	e := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			count++
			if count <= 5 {
				t.Log(path)
			}
		}
		return nil
	})
	t.Log("files", count, "error", e)
	names, e := fs.Glob(root, "@owasp_crs/*.conf")
	t.Log("alias configs", len(names), e)
	if e != nil || len(names) == 0 {
		t.Fatal("bundle aliases unavailable")
	}
}
