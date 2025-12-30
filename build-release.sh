#!/bin/bash
set -e

VERSION=${1:-"0.9.2"}
PROJECT_NAME="resh"

echo "Building ${PROJECT_NAME} v${VERSION} for multiple platforms..."

# Create release directory
mkdir -p releases/${VERSION}

# Build for different platforms
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

for target in "${TARGETS[@]}"; do
    echo "Building for ${target}..."
    
    # Install target if needed
    rustup target add ${target} || true
    
    # Build
    cargo build --release --target ${target}
    
    # Determine output name based on target
    case ${target} in
        *linux*)
            if [[ ${target} == *"musl"* ]]; then
                output_name="${PROJECT_NAME}-${VERSION}-linux-musl-x86_64"
            elif [[ ${target} == "aarch64"* ]]; then
                output_name="${PROJECT_NAME}-${VERSION}-linux-arm64"
            else
                output_name="${PROJECT_NAME}-${VERSION}-linux-x86_64"
            fi
            ;;
        *darwin*)
            if [[ ${target} == "aarch64"* ]]; then
                output_name="${PROJECT_NAME}-${VERSION}-macos-arm64"
            else
                output_name="${PROJECT_NAME}-${VERSION}-macos-x86_64"
            fi
            ;;
    esac
    
    # Copy binary to releases
    cp target/${target}/release/${PROJECT_NAME} releases/${VERSION}/${output_name}
    
    # Create tarball
    cd releases/${VERSION}
    tar -czf ${output_name}.tar.gz ${output_name}
    
    # Generate SHA256
    sha256sum ${output_name}.tar.gz > ${output_name}.tar.gz.sha256
    
    cd ../..
    
    echo "✓ Built ${output_name}"
done

echo "✓ All builds complete!"
echo "Release files in: releases/${VERSION}/"