package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	gitignorePath = ".gitignore"
	startMarker   = "# AUTO GENERATED SECTION BY CERTGEN (hack/tls-cert-gen/gitignore-gen.go), DO NOT EDIT BELOW"
	endMarker     = "# END CERTGEN SECTION. YOU MAY EDIT BELOW"
)

func writeGitIgnoreFile(filenames []string) error {
	// Read file (ignore error if not exists)
	gitignoreAbsolutePath := path.Join(projectRoot, gitignorePath)

	var lines []string
	data, err := os.ReadFile(gitignoreAbsolutePath) //gosec:disable G304 -- no part of this path is user-controlled. Project Root is defined in main(), it's a global variable, and gitignorePath is a const at the top of this file.
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}

	lines = strings.Split(string(data), "\n")

	// Find marker section
	startIdx, endIdx := -1, -1
	for i, l := range lines {
		if l == startMarker && startIdx == -1 {
			startIdx = i
		}
		if l == endMarker && startIdx != -1 {
			endIdx = i
			break
		}
	}

	// Build new section
	newSection := []string{startMarker, "\n"}
	newSection = append(newSection, filenames...)
	newSection = append(newSection, "\n", endMarker)

	// Replace or append section
	if startIdx != -1 && endIdx != -1 {
		// Replace section
		lines = append(lines[:startIdx], append(newSection, lines[endIdx+1:]...)...)
	} else {
		// Append, ensure there's an empty line before
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, newSection...)
	}

	// Write back
	out := strings.Join(lines, "\n")
	err = os.WriteFile(gitignoreAbsolutePath, []byte(out), 0o644) //gosec:disable G306 -- the file's existing permissions are 644. Restricting this to 600 or less would be problematic
	if err != nil {
		return fmt.Errorf("os.WriteFile: %w", err)
	}

	return nil
}

func generateGitignore(secrets secretsTypes, gitignorePtr *bool) error {
	if !*gitignorePtr {
		return nil
	}

	ignoredFilesAndLines := make([]string, 0)

	ignoredFilesAndLines = append(ignoredFilesAndLines, generateCertIgnoreLines(secrets.Certs)...)

	ignoredFilesAndLines = append(ignoredFilesAndLines, generateMtlsIgnoreLines(secrets.Mtls)...)

	ignoredFilesAndLines = append(ignoredFilesAndLines, generateHtpasswdIgnores(secrets.Htpasswds)...)

	ignoredFilesAndLines = append(ignoredFilesAndLines, generateJwksIgnores(secrets.Jwks)...)

	err := writeGitIgnoreFile(ignoredFilesAndLines)
	if err != nil {
		return fmt.Errorf("writeGitIgnoreFile: %w", err)
	}

	return nil
}

func generateCertIgnoreLines(certs []yamlSecret) []string {
	filesToIgnore := make([]string, 0)

	filesToIgnore = append(filesToIgnore, "\n#TLS Certificate secrets")

	for _, cert := range certs {
		filesToIgnore = append(filesToIgnore, path.Join(realSecretDirectory, cert.FileName))

		for _, symlink := range cert.Symlinks {
			filesToIgnore = append(filesToIgnore, strings.TrimPrefix(symlink, "/"))
		}
	}

	return filesToIgnore
}

func generateMtlsIgnoreLines(mtls []mtlsBundle) []string {
	filesToIgnore := make([]string, 0)

	filesToIgnore = append(filesToIgnore, "\n#mTLS Bundle Certificate secrets")

	for _, bundle := range mtls {
		ext := filepath.Ext(bundle.Ca.FileName)

		filesToIgnore = append(filesToIgnore,
			path.Join(realSecretDirectory, bundle.Ca.FileName),
			path.Join(realSecretDirectory, bundle.Client.FileName),
			path.Join(realSecretDirectory, bundle.Server.FileName),
			path.Join(realSecretDirectory, strings.ReplaceAll(bundle.Ca.FileName, ext, "-crl"+ext)), // ignore the crl file always
		)

		for _, symlink := range bundle.Ca.Symlinks {
			ext = filepath.Ext(symlink)
			crlSymlink := strings.ReplaceAll(symlink, ext, "-crl"+ext)

			filesToIgnore = append(filesToIgnore,
				strings.TrimPrefix(symlink, "/"),
				strings.TrimPrefix(crlSymlink, "/"))
		}

		for _, symlink := range bundle.Client.Symlinks {
			filesToIgnore = append(filesToIgnore, strings.TrimPrefix(symlink, "/"))
		}

		for _, symlink := range bundle.Server.Symlinks {
			filesToIgnore = append(filesToIgnore, strings.TrimPrefix(symlink, "/"))
		}
	}

	return filesToIgnore
}

func generateHtpasswdIgnores(htPasswds []htpasswdSecret) []string {
	filesToIgnore := make([]string, 0)

	filesToIgnore = append(filesToIgnore, "\n#TLS Certificate secrets")

	for _, htpw := range htPasswds {
		filesToIgnore = append(filesToIgnore, path.Join(realSecretDirectory, htpw.FileName))

		for _, symlink := range htpw.Symlinks {
			filesToIgnore = append(filesToIgnore, strings.TrimPrefix(symlink, "/"))
		}
	}

	return filesToIgnore
}

func generateJwksIgnores(jwks []jwkSecret) []string {
	filesToIgnore := make([]string, 0)

	filesToIgnore = append(filesToIgnore, "\n#Jwks secrets")

	for _, jwk := range jwks {
		filesToIgnore = append(filesToIgnore, path.Join(realSecretDirectory, jwk.FileName))

		for _, symlink := range jwk.Symlinks {
			filesToIgnore = append(filesToIgnore, strings.TrimPrefix(symlink, "/"))
		}
	}

	return filesToIgnore
}
