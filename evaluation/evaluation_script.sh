#!/bin/sh

root_dir=/tmp
namespace=$1
name=$2
dst_ip=$3

ports=$(cat "$root_dir"/all_ports)

# If has the fourth argument, then it is the experimental group.
if [ -z "$4" ]; then
  folder=outs/control
else
  folder=outs/exp
fi

mkdir -p "$root_dir"/"$folder"
out_file="$root_dir"/"$folder"/"$namespace"_"$name"_"$dst_ip"
echo "$namespace $name $dst_ip" > "$out_file"

for port in $ports; do
  out=$(nc -zvn -w 1 "$dst_ip" "$port" 2>&1)
  echo "$port $out" >> "$out_file"
done
