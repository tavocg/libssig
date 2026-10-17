package ssig

import "testing"

func TestVersion(t *testing.T) {
	major, minor, patch := Version()
	t.Logf("%d.%d.%d", major, minor, patch)
}
