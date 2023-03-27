# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

header0 = "# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl"
header1 = "# See the file 'LICENSE' for copying permission."

import sys
from pathlib import PosixPath
# arguments: BASE_DIR [run]
if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("First argument is the base directory to check")
        exit()
    if len(sys.argv) > 3:
        print("Too many argument")
        exit()
    if len(sys.argv) == 2 and sys.argv[2] != "run":
        print("Argument must be `run` or empty")
    base_path = sys.argv[1]
    base_path = PosixPath(base_path)
    if not base_path.exists():
        print(f"{str(base_path)} does not exists")
    if not base_path.is_dir():
        print(f"{str(base_path)} is not a directory")
    for file in base_path.rglob("*.py"):
        print(f"{file}")
        if file.stem == "__init__":
            print("\tSkipping")
            continue
        with open(file, "r+") as f:
            lines = f.readlines()
            if not (lines[0].strip() != header0.strip() and lines[1].strip() != header1.strip()):
                print("\tAdding header")
                continue
        if len(sys.argv) == 3 and sys.argv[2] == "run":
            with open(file, "w") as f:
                print("\tWritten")
                f.writelines([header0,"\n", header1, "\n", "\n"] + lines)


