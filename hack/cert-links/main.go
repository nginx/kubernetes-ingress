package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

type yamlTLS struct {
	ResourceKind string `yaml:"kind"`
	ResourceType string `yaml:"type"`
}

func main() {
	p, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}

	examples := filepath.Join(p, "examples")

	tests := filepath.Join(p, "tests")

	yamlActuals := make(map[string]os.FileInfo)
	yamlSymlinks := make(map[string]os.FileInfo)

	err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if !strings.HasPrefix(path, examples) && !strings.HasPrefix(path, tests) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("error while walking path %s: %w", path, err)
		}

		ext := filepath.Ext(d.Name())
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		if d.Type().IsRegular() || d.Type() == fs.ModeSymlink {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("error while opening file %s: %w", path, err)
			}

			fi, err := f.Stat()
			if err != nil {
				return fmt.Errorf("error while stating file %s: %w", path, err)
			}

			yk := yamlTLS{}

			contents, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("error while reading file %s: %w", path, err)
			}

			err = yaml.Unmarshal(contents, &yk)
			if err != nil {
				return fmt.Errorf("error while parsing file into tls yaml %s: %w", path, err)
			}

			if yk.ResourceType != "kubernetes.io/tls" {
				return nil
			}

			if yk.ResourceKind != "Secret" {
				return nil
			}

			if d.Type().IsRegular() {
				yamlActuals[path] = fi
				return nil
			}

			yamlSymlinks[path] = fi

			return nil
		}

		return nil
	})
	if err != nil {
		log.Fatalf("error walking path %s: %v", p, err)
	}

	actualsAndSymlinks := make(map[string][]string)

	for path := range yamlSymlinks {
		starget, err := filepath.EvalSymlinks(path)
		if err != nil {
			log.Fatalf("error while evaluating symlink %s: %v", path, err)
		}

		actualsAndSymlinks[starget] = append(actualsAndSymlinks[starget], path)
	}

	certInfo := make([]string, 0)

	for target, symlinks := range actualsAndSymlinks {
		fmt.Printf("Actual file: %s\n", strings.TrimPrefix(target, p))
		for _, path := range symlinks {
			fmt.Printf(" - : %s\n", strings.TrimPrefix(path, p))
		}

		info, err := getCertificateInfo(target)
		if err != nil {
			log.Fatalf("error while getting certificate info for %s: %v", target, err)
		}

		certInfo = append(certInfo, strings.TrimPrefix(target, p))
		certInfo = append(certInfo, info...)
	}

	onlyActualFiles := make(map[string]os.FileInfo)
	for path, info := range yamlActuals {
		if _, ok := actualsAndSymlinks[path]; !ok {
			onlyActualFiles[path] = info
		}
	}

	fmt.Print("\n\nPrinting only Actual Files with no symbolic links pointing to them\n\n")
	for path := range onlyActualFiles {
		if path == "/Users/g.javorszky/Projects/NIC/kubernetes-ingress/tests/data/default-server/invalid-tls-secret.yaml" {
			continue
		}

		fmt.Printf("%s\n", strings.TrimPrefix(path, p))

		info, err := getCertificateInfo(path)
		if err != nil {
			log.Fatalf("error while getting certificate info for %s: %v", path, err)
		}

		certInfo = append(certInfo, strings.TrimPrefix(path, p))
		certInfo = append(certInfo, info...)
	}

	err = os.WriteFile("certinfo.txt", []byte(strings.Join(certInfo, "\n")), fs.ModePerm)
	if err != nil {
		log.Fatalf("error while writing cert.txt: %v", err)
	}
}

func getCertificateInfo(path string) ([]string, error) {
	output := bytes.NewBuffer(nil)
	cmd := exec.Command("extract", path)
	cmd.Stdout = output
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error running extract command %s: %w", path, err)
	}

	parsedOutput := make([]string, 0)
	for _, line := range strings.Split(output.String(), "\n") {
		// skip the line with the modulus
		if strings.Contains(line, "Modulus:") {
			continue
		}

		// skip the lines with the hexdump modulus
		if strings.HasPrefix(line, "                    ") {
			continue
		}

		// skip the public key exponent
		if strings.Contains(line, "Exponent:") {
			continue
		}

		// skip the double printing of the x509v3 extensions
		if !strings.HasPrefix(line, "        ") {
			continue
		}

		parsedOutput = append(parsedOutput, line)
	}

	parsedOutput = append(parsedOutput, "")

	return parsedOutput, nil
}
