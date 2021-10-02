#!/bin/bash

if [ "$TRUNK_PROFILE" = "release" ]; then
    mv ./asset.css.bak ./asset.css
fi
