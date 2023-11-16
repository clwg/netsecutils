#!/bin/bash

# Define the base directory for the cmd and bin folders
BASE_DIR="$(pwd)"

# Directory where binaries will be stored
BIN_DIR="${BASE_DIR}/bin"

# Create the bin directory if it does not exist
mkdir -p "${BIN_DIR}"

# Navigate to the cmd directory
cd "${BASE_DIR}/cmd" || exit 1

# Loop through each subdirectory in the cmd directory
for DIR in */ ; do
    # Enter the directory
    cd "${DIR}" || continue

    # Extract the application name from the directory name
    APP_NAME=$(basename "$(pwd)")

    # Build the application and place the binary in the bin directory
    echo "Building ${APP_NAME}..."
    go build -o "${BIN_DIR}/${APP_NAME}"

    # Return to the cmd directory
    cd ..
done

echo "Build process completed."
