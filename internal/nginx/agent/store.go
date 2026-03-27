package agent

import (
	"sync"

	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/agent/v3/pkg/files"
)

const fileMode = "0644"

// ignoreFiles is a list of static base files in the nginx container that should
// not be touched by the agent during a ConfigApply. They are marked as
// "unmanaged" in the file overview.
var ignoreFiles = []string{
	"/etc/nginx/mime.types",
}

// File represents an nginx configuration file stored in memory.
type File struct {
	Meta     *pb.FileMeta
	Contents []byte
}

// FileStore is a thread-safe in-memory store of all NGINX configuration files.
// The NIC controller writes files here; the agent retrieves them via the
// FileService gRPC endpoint.
type FileStore struct {
	files         map[string]File
	configVersion string
	mu            sync.RWMutex
}

// NewFileStore returns a new empty FileStore.
func NewFileStore() *FileStore {
	return &FileStore{
		files: make(map[string]File),
	}
}

// Set adds or replaces a file in the store. Returns true if the file content
// changed (or is new).
func (s *FileStore) Set(name string, contents []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := files.GenerateHash(contents)

	if existing, ok := s.files[name]; ok {
		if existing.Meta.GetHash() == hash {
			return false
		}
	}

	s.files[name] = File{
		Meta: &pb.FileMeta{
			Name:        name,
			Hash:        hash,
			Size:        int64(len(contents)),
			Permissions: fileMode,
		},
		Contents: contents,
	}

	return true
}

// Delete removes a file from the store. Returns true if the file existed.
func (s *FileStore) Delete(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.files[name]; ok {
		delete(s.files, name)
		return true
	}
	return false
}

// GetFile returns the contents of a file by name and hash.
// Returns nil if the file is not found or the hash doesn't match.
func (s *FileStore) GetFile(name, hash string) ([]byte, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, ok := s.files[name]
	if !ok {
		return nil, ""
	}

	foundHash := f.Meta.GetHash()
	if hash != foundHash {
		return nil, foundHash
	}

	return f.Contents, foundHash
}

// GetFileOverviews returns the pb.File overview for all stored files, plus
// unmanaged entries for ignored base files. Also recomputes and returns the
// config version hash.
func (s *FileStore) GetFileOverviews() ([]*pb.File, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	overviews := make([]*pb.File, 0, len(s.files)+len(ignoreFiles))

	for _, f := range s.files {
		overviews = append(overviews, &pb.File{FileMeta: f.Meta})
	}

	// Add unmanaged files so the agent doesn't touch them
	for _, name := range ignoreFiles {
		overviews = append(overviews, &pb.File{
			FileMeta: &pb.FileMeta{
				Name:        name,
				Permissions: fileMode,
			},
			Unmanaged: true,
		})
	}

	s.configVersion = files.GenerateConfigVersion(overviews)

	return overviews, s.configVersion
}

// GetConfigVersion returns the current config version without recomputing.
func (s *FileStore) GetConfigVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.configVersion
}

// FileCount returns the number of managed files in the store.
func (s *FileStore) FileCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.files)
}
