#!/usr/bin/env bash

if [ ! -f "./asset.css" ]; then
    tailwindcss -o ./asset.css
fi
if [ "$TRUNK_PROFILE" = "release" ]; then
    cp ./asset.css ./asset.css.bak
    NODE_ENV=production tailwindcss -c ./tailwind.config.js -o ./asset.css --minify
fi
