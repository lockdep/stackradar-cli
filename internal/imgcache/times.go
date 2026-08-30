package imgcache

import (
	"os"
	"time"
)

var nowFunc = time.Now

// lastUsed is the entry's modification time: Touch bumps it on every hit,
// which is portable, unlike atime.
func lastUsed(info os.FileInfo) int64 { return info.ModTime().UnixNano() }
