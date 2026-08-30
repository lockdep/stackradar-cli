package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lockdep/stackradar-cli/internal/imgcache"
)

var cacheOpts struct {
	dir string
}

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Inspect or clear the layer cache that speeds up repeat scans",
	Long: `Pulled image layers are kept on disk (by digest) so that scanning the same
cluster again downloads only what changed. The cache is pruned to ` + humanBytes(imgcache.DefaultMaxBytes) + `
after every scan; nothing else is stored in it.`,
}

var cacheInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show where the cache is and how big it is",
	RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := openCache()
		if err != nil {
			return err
		}
		st, err := c.Stats()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n%d layers, %s\n", c.Dir(), st.Layers, humanBytes(st.Bytes))
		return nil
	},
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete every cached layer",
	RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := openCache()
		if err != nil {
			return err
		}
		st, err := c.Clear()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Removed %d layers (%s) from %s\n", st.Layers, humanBytes(st.Bytes), c.Dir())
		return nil
	},
}

func openCache() (*imgcache.Cache, error) {
	dir := cacheOpts.dir
	if dir == "" {
		var err error
		if dir, err = imgcache.DefaultDir(); err != nil {
			return nil, err
		}
	}
	return imgcache.Open(dir)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func init() {
	cacheCmd.PersistentFlags().StringVar(&cacheOpts.dir, "cache-dir", "", "cache directory (default: "+cacheDirHint()+")")
	cacheCmd.AddCommand(cacheInfoCmd, cacheClearCmd)
	rootCmd.AddCommand(cacheCmd)
}
