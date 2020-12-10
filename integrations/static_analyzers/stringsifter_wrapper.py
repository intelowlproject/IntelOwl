#!/usr/bin/env python3
import json
from argparse import ArgumentParser
from subprocess import Popen, PIPE

parser = ArgumentParser()
sub_parser = parser.add_subparsers()

# flarestrings
flarestrings = sub_parser.add_parser("flarestrings", help="To access flarestrings")
flarestrings.set_defaults(which="flarestrings")
flarestrings.add_argument("file_path")

# rank_strings
rank_strings = sub_parser.add_parser("rank_strings", help="To access rank_strings")
rank_strings.set_defaults(which="rank_strings")


rank_strings.add_argument(
    "--limit",
    "-l",
    help="limit output to the top `limit` ranked strings",
)
rank_strings.add_argument("--strings", help="Strings to be Ranked")
args = parser.parse_args()

if args.which == "flarestrings":
    p = Popen(["/usr/local/bin/flarestrings", args.file_path], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
else:
    strings = json.loads(args.strings)
    p = Popen(
        ["/usr/local/bin/rank_strings", f"-l {args.limit}"],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    out, err = p.communicate("\n".join(strings).encode())

output_strings = out.decode().splitlines()
print(json.dumps(output_strings))
