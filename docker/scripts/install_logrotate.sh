# Get the directory path of the script (including symbolic link)
dir="$(dirname "$(readlink -f "$0")")"

sudo cp -r "$dir/logrotate" /etc/logrotate.d