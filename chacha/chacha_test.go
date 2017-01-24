// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import "encoding/hex"

func toHex(b []byte) string {
	return hex.EncodeToString(b)
}
