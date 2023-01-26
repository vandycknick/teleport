/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sftp

import (
	"context"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/gravitational/trace"
	"github.com/pkg/sftp"
)

// remoteFS provides API for accessing the files on
// the local file system
type remoteFS struct {
	c *sftp.Client
}

func (r *remoteFS) Type() string {
	return "remote"
}

func (r *remoteFS) Stat(ctx context.Context, path string) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fi, err := r.c.Stat(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return fi, nil
}

func (r *remoteFS) ReadDir(ctx context.Context, path string) ([]os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fileInfos, err := r.c.ReadDir(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return fileInfos, nil
}

func (r *remoteFS) Open(ctx context.Context, path string) (fs.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := r.c.Open(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return f, nil
}

func (r *remoteFS) Create(ctx context.Context, path string, mode os.FileMode) (io.WriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := r.c.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return f, nil
}

func (r *remoteFS) Mkdir(ctx context.Context, path string, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	err := r.c.MkdirAll(path, mode)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (r *remoteFS) Chmod(ctx context.Context, path string, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return trace.Wrap(r.c.Chmod(path, mode))
}

func (r *remoteFS) Chtimes(ctx context.Context, path string, atime, mtime time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return trace.Wrap(r.c.Chtimes(path, atime, mtime))
}
