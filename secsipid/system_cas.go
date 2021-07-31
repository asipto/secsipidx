package secsipid

/** Copied and pasted from go standard library: "crypto/x509" package!! **/

/*
 * As of Go version 1.16.6, it is impossible to reload the system CA pool, so
 * testing whether 'SJWTPubKeyVerify()' actually uses them is impossible
 * (unless you generate a real certificate signed by a real CA).
 *
 * This copy/paste solution allows the system CAs to be reloaded manually,
 * by calling 'ResetSystemCertPool()' before calling 'SystemCertPool()',
 * so they can be mocked by writing your own CA certs to a file and changing
 * the environment variables: SSL_CERT_FILE and SSL_CERT_DIR.
 */

import (
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// certFileEnv is the environment variable which identifies where to locate
	// the SSL certificate file. If set this overrides the system default.
	certFileEnv = "SSL_CERT_FILE"

	// certDirEnv is the environment variable which identifies which directory
	// to check for SSL certificate files. If set this overrides the system default.
	// It is a colon separated list of directories.
	// See https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html.
	certDirEnv = "SSL_CERT_DIR"
)

var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

var certDirectories = []string{
	"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
	"/etc/pki/tls/certs",           // Fedora/RHEL
	"/system/etc/security/cacerts", // Android
}

var systemCertPool *x509.CertPool = nil

func SystemCertPool() (*x509.CertPool, error) {
	if systemCertPool != nil {
		return systemCertPool, nil
	}
	systemRoots, err := loadSystemRoots()
	if err != nil {
		return nil, err
	}
	systemCertPool = systemRoots
	return systemCertPool, nil
}

func ResetSystemCertPool() {
	systemCertPool = nil
}

// On Unix systems other than macOS the environment variables SSL_CERT_FILE and
// SSL_CERT_DIR can be used to override the system default locations for the SSL
// certificate file and SSL certificate files directory, respectively. The
// latter can be a colon-separated list.
func loadSystemRoots() (*x509.CertPool, error) {
	roots := x509.NewCertPool()

	files := certFiles
	if f := os.Getenv(certFileEnv); f != "" {
		files = []string{f}
	}

	var firstErr error
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			break
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	dirs := certDirectories
	if d := os.Getenv(certDirEnv); d != "" {
		// OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator.
		// See:
		//  * https://golang.org/issue/35325
		//  * https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html
		dirs = strings.Split(d, ":")
	}

	for _, directory := range dirs {
		fis, err := readUniqueDirectoryEntries(directory)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, fi := range fis {
			data, err := os.ReadFile(directory + "/" + fi.Name())
			if err == nil {
				roots.AppendCertsFromPEM(data)
			}
		}
	}

	if len(roots.Subjects()) > 0 || firstErr == nil {
		return roots, nil
	}

	return nil, firstErr
}

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether fi in dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool {
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.Contains(target, "/")
}
