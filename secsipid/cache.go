package secsipid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type urlCache interface {
	Get(urlVal string) ([]byte, error)
	Set(urlVal string, data []byte) error
}

type fileURLCache struct {
	dirPath  string
	expire   int
	nameMode string
}

func newFileURLCache(dirPath string, expire int, nameMode string) *fileURLCache {
	return &fileURLCache{
		dirPath:  dirPath,
		expire:   expire,
		nameMode: nameMode,
	}
}

func (c *fileURLCache) filePath(urlVal string) string {
	var fileName string
	switch c.nameMode {
	case "sha256":
		hashVal := sha256.Sum256([]byte(urlVal))
		fileName = "url_" + hex.EncodeToString(hashVal[:])
	default:
		fileName = strings.ReplaceAll(urlVal, "://", "_")
		fileName = strings.ReplaceAll(fileName, "/", "_")
	}
	if c.dirPath != "" {
		return filepath.Join(c.dirPath, fileName)
	}
	return fileName
}

func (c *fileURLCache) Get(urlVal string) ([]byte, error) {
	filePath := c.filePath(urlVal)
	fileStat, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	if int(time.Since(fileStat.ModTime()).Seconds()) > c.expire {
		_ = os.Remove(filePath)
		return nil, nil
	}
	return os.ReadFile(filePath)
}

func (c *fileURLCache) Set(urlVal string, data []byte) error {
	filePath := c.filePath(urlVal)
	cacheDir := filepath.Dir(filePath)
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(cacheDir, ".secsipid-cache-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err = tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err = tempFile.Chmod(0640); err != nil {
		tempFile.Close()
		return err
	}
	if err = tempFile.Close(); err != nil {
		return err
	}

	return os.Rename(tempPath, filePath)
}

func (o *SJWTLibOptions) refreshURLCache() {
	if o.cacheDirPath == "" {
		o.cache = nil
		return
	}
	o.cache = newFileURLCache(o.cacheDirPath, o.cacheExpire, o.cacheNameMode)
}

func (o *SJWTLibOptions) fileURLCache() *fileURLCache {
	return newFileURLCache(o.cacheDirPath, o.cacheExpire, o.cacheNameMode)
}

// SJWTGetURLCacheFilePath returns the configured filesystem cache path for a URL.
func SJWTGetURLCacheFilePath(urlVal string) string {
	options := globalLibOptionsSnapshot()
	return options.fileURLCache().filePath(urlVal)
}

// SJWTGetURLCachedContent reads URL content from the configured cache.
func SJWTGetURLCachedContent(urlVal string) ([]byte, error) {
	options := globalLibOptionsSnapshot()
	cache := options.cache
	if cache == nil {
		cache = options.fileURLCache()
	}
	return cache.Get(urlVal)
}

// SJWTSetURLCachedContent writes URL content to the configured cache.
func SJWTSetURLCachedContent(urlVal string, data []byte) error {
	options := globalLibOptionsSnapshot()
	cache := options.cache
	if cache == nil {
		cache = options.fileURLCache()
	}
	return cache.Set(urlVal, data)
}
