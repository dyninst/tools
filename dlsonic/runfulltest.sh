#!/bin/bash

for d in /bin /sbin /lib* /usr; do
  if [ -d "$d" ]; then
    echo "SCANNING $d" >&2
    find "$d" -type f | while read p; do
      if file "$p" | grep -q '^.*:.*ELF'; then
        echo "$p"
      fi
    done
  fi
done > elf.files

python dlsummary.py --input elf.files --raw-output raw.txt --csv-output results.csv