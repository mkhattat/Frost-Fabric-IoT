#!/bin/bash

rm ./assetTransfer

go build -o assetTransfer -ldflags="-r ./lib" assetTransfer.go

./assetTransfer
