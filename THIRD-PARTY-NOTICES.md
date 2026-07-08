# Third-party notices

`ntcompress` is licensed under Apache-2.0 (see `LICENSE`). Parts of it are derived from third-party sources, whose notices and licenses are reproduced below. Each ported module also carries `file:line` citations to its upstream source in its own docstring.

## Provenance summary

| Component | Relationship to upstream | Upstream | Upstream license |
|---|---|---|---|
| `ese/xpress9.py` (XPRESS9 codec) | Port (derivative work) | Extensible-Storage-Engine `dev/ese/src/_xpress9/` | MIT (Microsoft) |
| `ese/checksums.py` (CRC-32C, CRC-64) | Port of the CRC loops/constants | Extensible-Storage-Engine `dev/ese/src/_xpress10/xpress10sw.cxx`, `dev/ese/src/os/encrypt.cxx` | MIT (Microsoft) |
| `ese/__init__.py`, `ese/_registry.py`, `ese/{sevenbit_ascii,sevenbit_unicode,xpress,scrub,xpress10}.py` | Constants/behaviour transcribed with citations | Extensible-Storage-Engine `dev/ese/src/ese/compression.cxx` | MIT (Microsoft) |
| `ntdll/{xpress,xpress_huff,lznt1}.py` | Spec-derived implementation | `[MS-XCA]` Xpress Compression Algorithm | Microsoft Open Specifications (see below) |
| `ese/lz4.py` (block format) | Format-derived implementation (no upstream source used) | LZ4 Block Format, Yann Collet | BSD-2-Clause |

"Port" means the code follows Microsoft's MIT-licensed C closely enough to be a derivative work; it is attributed here and is NOT clean-room. "Spec-derived" means the code was written from a published specification, not from source.

## Microsoft Extensible Storage Engine — MIT License

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
```

## Microsoft Open Specification [MS-XCA]

The Plain LZ77, LZ77+Huffman, and LZNT1 codecs are implemented from `[MS-XCA]: Xpress Compression Algorithm`, a Microsoft Open Specification. Microsoft's Open Specifications IPR notice grants the right to copy and distribute the code samples and schemas contained in the documentation for the purpose of developing implementations. This project cites `[MS-XCA] §x.y` for each rule it implements and pins the specification revision in `research/spec/VERSIONS.md` (implemented against v10.0). No Microsoft source code is used for these codecs.

## LZ4 block format — BSD-2-Clause

`ese/lz4.py` implements the public LZ4 block format. It was written from the format description, not from liblz4 source. The reference implementation is:

```
LZ4 - Fast LZ compression algorithm
Copyright (C) 2011-present, Yann Collet.

BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. ...
```
