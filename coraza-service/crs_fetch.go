// CRS fetching, done once at startup — replaces the old standalone
// fetch-crs.sh: CRS_VERSION now lives in .env, and "latest" is resolved
// against GitHub at startup rather than requiring a manual pinned re-run.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const crsTagsURL = "https://api.github.com/repos/coreruleset/coreruleset/tags"

// ensureCRS makes sure crsDir holds the requested CRS version, fetching it if
// missing or out of date. "latest" is resolved to a real version first. A
// dir that already matches the resolved version is left untouched — no
// network call, no delay — so a normal container restart doesn't re-fetch.
func ensureCRS(crsDir, requestedVersion, paranoiaLevel string) error {
	version, err := resolveCRSVersion(requestedVersion)
	if err != nil {
		return fmt.Errorf("resolve CRS version %q: %w", requestedVersion, err)
	}

	if current, err := os.ReadFile(filepath.Join(crsDir, "VERSION")); err == nil && strings.TrimSpace(string(current)) == version {
		log.Printf("CRS v%s already present at %s, skipping fetch", version, crsDir)
	} else {
		log.Printf("fetching CRS v%s into %s...", version, crsDir)
		if err := fetchCRS(crsDir, version); err != nil {
			return fmt.Errorf("fetch CRS v%s: %w", version, err)
		}
		log.Printf("CRS v%s fetched successfully", version)
	}

	// Independent of whether a fetch actually happened above: CRS_PARANOIA_LEVEL
	// can change across restarts without a CRS version bump, and main.conf's
	// Include list needs paranoia-level.conf to exist regardless of which
	// branch ran.
	level := writeParanoiaConf(crsDir, paranoiaLevel)
	if err := writeMainConf(crsDir); err != nil {
		return fmt.Errorf("writing main.conf: %w", err)
	}
	log.Printf("CRS paranoia level set to %d", level)
	return nil
}

func resolveCRSVersion(requested string) (string, error) {
	if requested != "latest" {
		return requested, nil
	}

	req, err := http.NewRequest(http.MethodGet, crsTagsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "coraza-service-crs-fetcher")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("querying %s: %w", crsTagsURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("querying %s: unexpected status %s", crsTagsURL, resp.Status)
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("decoding tags response: %w", err)
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no tags returned for coreruleset")
	}
	// GitHub's tags API returns them newest-first.
	version := strings.TrimPrefix(tags[0].Name, "v")
	log.Printf("resolved CRS \"latest\" -> v%s", version)
	return version, nil
}

// fetchCRS downloads the CRS release tarball and lays out the same flat
// directory fetch-crs.sh used to produce: crs-setup.conf, REQUEST-*.conf and
// *.data flattened together (Coraza resolves @pmFromFile references relative
// to whichever directory main.conf lives in — see buildWAF), plus a
// generated main.conf, VERSION and FETCHED_AT.
func fetchCRS(crsDir, version string) error {
	url := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/refs/tags/v%s.tar.gz", version)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gz.Close()

	// crsDir is itself the bind-mount point (docker-compose.yml), so it can't
	// be removed and recreated like a normal directory — the kernel refuses
	// to unlink an active mount ("device or resource busy"). Clear its
	// contents instead, leaving the directory (the mount) itself in place.
	if err := clearDirContents(crsDir); err != nil {
		return fmt.Errorf("clearing %s: %w", crsDir, err)
	}

	prefix := fmt.Sprintf("coreruleset-%s/", version)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasPrefix(hdr.Name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, prefix)

		var destName string
		switch {
		case rel == "crs-setup.conf.example":
			destName = "crs-setup.conf"
		case strings.HasPrefix(rel, "rules/") && strings.HasPrefix(path.Base(rel), "REQUEST-") && strings.HasSuffix(rel, ".conf"):
			destName = path.Base(rel)
		case strings.HasPrefix(rel, "rules/") && strings.HasSuffix(rel, ".data"):
			destName = path.Base(rel)
		default:
			continue
		}

		if err := writeTarEntry(filepath.Join(crsDir, destName), tr); err != nil {
			return fmt.Errorf("writing %s: %w", destName, err)
		}
	}

	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing VERSION: %w", err)
	}
	fetchedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if err := os.WriteFile(filepath.Join(crsDir, "FETCHED_AT"), []byte(fetchedAt+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing FETCHED_AT: %w", err)
	}

	return nil
}

func clearDirContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0o755)
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func writeTarEntry(destPath string, r io.Reader) error {
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

// writeMainConf regenerates main.conf unconditionally — cheap, local,
// config-only, and needs to run every startup (not just on a fresh CRS
// fetch) since paranoia-level.conf's content can change independently via
// CRS_PARANOIA_LEVEL.
//
// Paths are absolute, matching crsDir: Coraza's parser does NOT resolve a
// glob Include relative to the including file's directory — only a
// single-file Include gets that treatment. A relative glob here would
// silently match nothing. See buildWAF's comment for why main.conf and the
// .data files must live side by side.
func writeMainConf(crsDir string) error {
	mainConf := fmt.Sprintf(mainConfTemplate, crsDir, crsDir, crsDir)
	return os.WriteFile(filepath.Join(crsDir, "main.conf"), []byte(mainConf), 0o644)
}

const mainConfTemplate = `# Generated by coraza-service on startup (crs_fetch.go) — don't hand-edit,
# edit crs-setup.conf directly or add local rules to crs-exclusions/
# instead (see coraza-service/crs-exclusions/crs_exclusion.conf).
Include %s/crs-setup.conf
Include %s/paranoia-level.conf
Include %s/REQUEST-*.conf
`

// writeParanoiaConf renders the CRS_PARANOIA_LEVEL override and also drops a
// plain PARANOIA_LEVEL file next to VERSION/FETCHED_AT so the dashboard can
// display it the same way (see dashboard/app/main.py's active_config).
// Included after crs-setup.conf on purpose: crs-setup.conf.example ships its
// own paranoia-level SecAction at these exact ids (900000/900001) commented
// out by default, so ours is the only one actually active — same ids,
// loaded later, so ours is what CRS's rule files see (last setvar wins
// within the same phase).
func writeParanoiaConf(crsDir, raw string) int {
	level, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || level < 1 || level > 4 {
		if raw != "" {
			log.Printf("CRS_PARANOIA_LEVEL %q invalid (must be 1-4), defaulting to 1", raw)
		}
		level = 1
	}
	conf := fmt.Sprintf(paranoiaConfTemplate, level, level)
	if err := os.WriteFile(filepath.Join(crsDir, "paranoia-level.conf"), []byte(conf), 0o644); err != nil {
		log.Printf("writing paranoia-level.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "PARANOIA_LEVEL"), []byte(strconv.Itoa(level)+"\n"), 0o644); err != nil {
		log.Printf("writing PARANOIA_LEVEL: %v", err)
	}
	return level
}

const paranoiaConfTemplate = `# Generated by coraza-service on startup from CRS_PARANOIA_LEVEL (.env) —
# don't hand-edit, change CRS_PARANOIA_LEVEL and restart coraza-service.
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.blocking_paranoia_level=%d"
SecAction \
    "id:900001,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.detection_paranoia_level=%d"
`
