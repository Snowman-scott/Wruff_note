package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const EnvDBPassword = "WRUFF_DB_PASSWORD"

var validSSLModes = map[string]bool{
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

// host, port, name, user, pass

type Config struct {
	Backend string `json:"backend"`
	Host    string `json:"dbHost"`
	Port    int    `json:"dbPort"`
	Name    string `json:"dbName"`
	User    string `json:"dbUser"`
	Pass    string `json:"-"`
	SSLM    string `json:"sslMod"`
	File    string `json:"file"`
}

// Path returns the config directory.
func Path() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "wruff-note"), nil
}

func Default() Config {
	return Config{
		Backend: "postgres",
		SSLM:    "require",
	}
}

func DefaultPort(Backend string) int {
	if Backend == "postgres" {
		return 5432
	} else if Backend == "mariadb" {
		return 3306
	}
	return 0
}

func Load(confPath string) (Config, error) {
	Conf := Default()

	filePath := filepath.Join(confPath, "config.json")
	file, err := os.Open(filePath)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&Conf); err != nil {
		return Config{}, err
	}

	Conf.Pass = os.Getenv(EnvDBPassword)

	if err := Conf.Validate(); err != nil {
		return Config{}, err
	}

	return Conf, nil
}

func Save(confPath string, Conf Config) error {
	filePath := filepath.Join(confPath, "config.json")

	if err := os.MkdirAll(confPath, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := os.Chmod(filePath, 0o600); err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(Conf)
}

// CheckFields checks everything except the password. Setup can call this.
func (c *Config) CheckFields() error {
	switch c.Backend {
	case "postgres", "mariadb":
		if c.Host == "" {
			return errors.New("host is required")
		}
		if c.Port == 0 {
			return errors.New("port is required")
		}
		if c.Name == "" {
			return errors.New("database name is required")
		}
		if c.User == "" {
			return errors.New("user is required")
		}
		if c.Backend == "postgres" && !validSSLModes[c.SSLM] {
			return fmt.Errorf("invalid sslmode %q (use require, verify-ca or verify-full)", c.SSLM)
		}
	case "sqlite":
		if c.File == "" {
			return errors.New("sqlite file path is required")
		}
	default:
		return fmt.Errorf("unknown backend %q", c.Backend)
	}

	return nil
}

// Validate is the full check. Load calls this.
func (c *Config) Validate() error {
	if err := c.CheckFields(); err != nil {
		return err
	}

	if (c.Backend == "postgres" || c.Backend == "mariadb") && c.Pass == "" {
		return fmt.Errorf("database password not set (set %s)", EnvDBPassword)
	}

	return nil
}
