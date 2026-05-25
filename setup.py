#!/usr/bin/env python
# Copyright Drape.io. SPDX-License-Identifier: Apache-2.0

from setuptools import Extension, setup

setup(
    build_golang={"root": "github.com/drape-io/pytrivydb/go-src"},
    ext_modules=[
        Extension("pytrivydb._pytrivydb", ["go-src/cmd/pytrivydb/main.go"]),
    ],
    cffi_modules=["pytrivydb/build_cffi.py:ffi"],
)
