#!/bin/bash
echo "Setting up the environment..."

pythonScriptPath="./main.py"
batFileName="fabt"
targetPath="/usr/local/bin"

currentDir=$(pwd)

pythonScriptFullPath="$currentDir/$pythonScriptPath"

if [ ! -d "$targetPath" ]; then
    sudo mkdir -p "$targetPath"
fi

echo "#!/bin/bash" > "$targetPath/$batFileName"
echo "python3 \"$pythonScriptFullPath\" \"\$@\"" >> "$targetPath/$batFileName"

sudo chmod +x "$targetPath/$batFileName"

echo "Done! Run 'fabt -v' to start the program."

