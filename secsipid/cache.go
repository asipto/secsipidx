package secsipid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type urlCache interface {
	Get(ctx context.Context, urlVal string) ([]byte, error)
	Set(ctx context.Context, urlVal string, data []byte) error
	Close() error
}

type fileURLCache struct {
	dirPath  string
	expire   int
	nameMode string
}

var _ urlCache = (*fileURLCache)(nil)

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

func (c *fileURLCache) Get(_ context.Context, urlVal string) ([]byte, error) {
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

func (c *fileURLCache) Set(_ context.Context, urlVal string, data []byte) error {
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

func (c *fileURLCache) Close() error {
	return nil
}

type errorURLCache struct {
	err error
}

func (c *errorURLCache) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, c.err
}

func (c *errorURLCache) Set(_ context.Context, _ string, _ []byte) error {
	return c.err
}

func (c *errorURLCache) Close() error {
	return nil
}

func (o *SJWTLibOptions) refreshURLCache() {
	switch o.cacheBackend {
	case "", "file":
		if o.cacheDirPath == "" {
			o.cache = nil
			return
		}
		o.cache = newFileURLCache(o.cacheDirPath, o.cacheExpire, o.cacheNameMode)
	case "none":
		o.cache = nil
	case "redis":
		cache, err := newRedisURLCache(o.redisURL, o.redisKeyPrefix, o.cacheExpire, o.redisTimeout)
		if err != nil {
			o.cache = &errorURLCache{err: err}
			return
		}
		o.cache = cache
	default:
		o.cache = &errorURLCache{err: fmt.Errorf("unsupported cache backend %q", o.cacheBackend)}
	}
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
	return cache.Get(context.Background(), urlVal)
}

// SJWTSetURLCachedContent writes URL content to the configured cache.
func SJWTSetURLCachedContent(urlVal string, data []byte) error {
	options := globalLibOptionsSnapshot()
	cache := options.cache
	if cache == nil {
		cache = options.fileURLCache()
	}
	return cache.Set(context.Background(), urlVal, data)
}
