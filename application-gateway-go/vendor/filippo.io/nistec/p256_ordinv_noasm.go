// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build purego || (!amd64 && !arm64)

package nistec

import "errors"

func p256OrdInverse(k []byte) ([]byte, error) {
	return nil, errors.New("unimplemented")
}
