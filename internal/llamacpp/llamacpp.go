// Package llamacpp installs the pinned llama.cpp llama-server binary used to
// run inference locally. Binaries come from official ggml-org releases and are
// verified against hard-coded SHA-256 digests before extraction.
package llamacpp

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PinnedVersion is the llama.cpp release this CLI build expects. Bump it (and
// the digests below) together with a CLI release.
const PinnedVersion = "b10549"

const releaseBaseURL = "https://github.com/ggml-org/llama.cpp/releases/download/" + PinnedVersion

type asset struct {
	file   string
	sha256 string
}

// pinnedAssets maps GOOS/GOARCH to the official CPU build and its digest.
var pinnedAssets = map[string]asset{
	"linux/amd64": {
		file:   "llama-" + PinnedVersion + "-bin-ubuntu-x64.tar.gz",
		sha256: "66b26d8cb3ab8edaf5a12bfe642b8f00844925f614f196a96a222b7ed1582c1d",
	},
	"linux/arm64": {
		file:   "llama-" + PinnedVersion + "-bin-ubuntu-arm64.tar.gz",
		sha256: "461d4b8775807fe39a418ea82b69c477e0e861ab8c5141af20d9c2c4975a3f2a",
	},
	"darwin/amd64": {
		file:   "llama-" + PinnedVersion + "-bin-macos-x64.tar.gz",
		sha256: "94177680843a187881ae54021bbad8211c40797cab0df923ef17ee735e3ade09",
	},
	"darwin/arm64": {
		file:   "llama-" + PinnedVersion + "-bin-macos-arm64.tar.gz",
		sha256: "71e4b31afb020d6b71894eb8d1f2c0693038aec3f41f672f9fafb5055c8f2226",
	},
	"windows/amd64": {
		file:   "llama-" + PinnedVersion + "-bin-win-cpu-x64.zip",
		sha256: "11d38f2ed878489b2c3d02b3d1a67683c02fbfb3d265876b9ede749a8dff5f1c",
	},
}

const serverBinary = "llama-server"

// DefaultModelURL is the GGUF downloaded by `plenarai setup` when the user
// does not supply their own model path or URL. It points at the official
// vendor repository on Hugging Face; community mirrors come and go.
const DefaultModelURL = "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf"

// DefaultModelName is the identifier reported to the backend for the default model.
const DefaultModelName = "qwen2.5-3b-instruct-q4_k_m"

// ServerPath returns the expected llama-server location inside binDir.
func ServerPath(binDir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(binDir, serverBinary+".exe")
	}
	return filepath.Join(binDir, serverBinary)
}

// Installed reports whether the pinned llama-server binary exists.
func Installed(binDir string) bool {
	_, err := os.Stat(ServerPath(binDir))
	return err == nil
}

// Install downloads and extracts the pinned llama-server into binDir.
// It is idempotent: an existing verified binary short-circuits.
func Install(binDir string) error {
	key := runtime.GOOS + "/" + runtime.GOARCH
	a, ok := pinnedAssets[key]
	if !ok {
		return fmt.Errorf("no pinned llama.cpp build for %s", key)
	}

	serverPath := ServerPath(binDir)
	if _, err := os.Stat(serverPath); err == nil {
		return nil
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}

	url := releaseBaseURL + "/" + a.file
	fmt.Printf("Downloading llama.cpp %s (%s)...\n", PinnedVersion, key)
	archivePath := filepath.Join(binDir, a.file)
	defer os.Remove(archivePath)
	if err := downloadVerified(url, archivePath, a.sha256); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	fmt.Println("Extracting llama-server...")
	var err error
	switch {
	case strings.HasSuffix(a.file, ".tar.gz"):
		err = extractTarGz(archivePath, binDir)
	case strings.HasSuffix(a.file, ".zip"):
		err = extractZip(archivePath, binDir)
	default:
		err = fmt.Errorf("unsupported archive format")
	}
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	if _, err := os.Stat(serverPath); err != nil {
		return fmt.Errorf("%s not found in archive", serverBinary)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(serverPath, 0o755); err != nil {
			return err
		}
	}
	marker := filepath.Join(binDir, "VERSION")
	if err := os.WriteFile(marker, []byte(PinnedVersion+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("llama-server installed at %s\n", serverPath)
	return nil
}

func downloadVerified(url, dest, wantSHA string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned status %d", url, resp.StatusCode)
	}

	tmp := dest + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	var written int64
	buf := make([]byte, 1<<20)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				os.Remove(tmp)
				return werr
			}
			hasher.Write(buf[:n])
			written += int64(n)
			fmt.Printf("  %d MB\r", written/(1<<20))
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			os.Remove(tmp)
			return rerr
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Println()

	got := hex.EncodeToString(hasher.Sum(nil))
	if got != wantSHA {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch: got %s want %s", got, wantSHA)
	}
	return os.Rename(tmp, dest)
}

// extractTarGz extracts all entries into destDir. llama-server is dynamically
// linked against the bundled libggml/libllama libraries (RPATH $ORIGIN), so
// regular files and symlinks must land in the same flat directory.
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Flatten; reject traversal attempts in crafted archives.
		name := filepath.Base(hdr.Name)
		if name == "." || name == ".." || name == "/" {
			continue
		}
		outPath := filepath.Join(destDir, name)

		switch hdr.Typeflag {
		case tar.TypeReg:
			mode := os.FileMode(hdr.Mode & 0o777)
			if mode&0o100 == 0 {
				mode |= 0o755 // shipped binaries must stay executable
			}
			out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			os.Remove(outPath)
			if err := os.Symlink(filepath.Base(hdr.Linkname), outPath); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	return nil
}

// extractZip extracts all entries into destDir (Windows ships DLLs alongside
// the exe, same flat layout as the Linux/macOS tarballs).
func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(zf.Name)
		if name == "." || name == ".." {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		outPath := filepath.Join(destDir, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// DownloadModel streams a GGUF file to dest with progress output.
func DownloadModel(url, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("Model already present: %s\n", dest)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	fmt.Printf("Downloading model (%s)...\n", filepath.Base(dest))
	tmp := dest + ".part"
	if err := httpDownload(url, tmp); err != nil {
		os.Remove(tmp)
		if strings.Contains(err.Error(), "status 401") || strings.Contains(err.Error(), "status 403") {
			return fmt.Errorf("%w\nThe model source denied access (it may now require login or have moved).\nUse a different source: plenarai setup --model-url <URL> or --model-path <file.gguf>", err)
		}
		return err
	}
	return os.Rename(tmp, dest)
}

func httpDownload(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned status %d", url, resp.StatusCode)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}

	var written int64
	buf := make([]byte, 1<<20)
	lastPct := -1
	total := resp.ContentLength
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return werr
			}
			written += int64(n)
			if total > 0 {
				pct := int(100 * written / total)
				if pct/5 != lastPct/5 {
					fmt.Printf("  %d%% (%d MB / %d MB)\r", pct, written/(1<<20), total/(1<<20))
					lastPct = pct
				}
			} else if written/(1<<20) != (written-int64(n))/(1<<20) {
				fmt.Printf("  %d MB\r", written/(1<<20))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	fmt.Println()
	return out.Close()
}
