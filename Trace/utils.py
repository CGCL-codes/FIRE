

import csv
import difflib
import hashlib
import os
from typing import List








vuln_to_patch_dict = {}


TRACE_DIR = os.path.dirname(os.path.realpath(__file__))


def norm_line(line_list : List[str]) -> List[str]:
    return list(map(lambda line: line.strip(), line_list))

def get_file_pairs(file_path):
    with open(file_path, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            yield row["old"], row["new"]
            
        
def diff_lines(left_list, right_list):
    left_list = norm_line(left_list)
    right_list = norm_line(right_list)

    differ = difflib.Differ()
    diff = list(differ.compare(left_list, right_list))

    left_diff = []
    right_diff = []

    left = 0
    right = 0
    for line in diff:
        if line.startswith("- "):
            left_diff.append(left_list[left])
            left += 1
        elif line.startswith("+ "):
            right_diff.append(right_list[right])
            right += 1 
        elif not line.startswith("? ") and line.strip() != "":
            left += 1
            right += 1

    return left_diff, right_diff

def line_hash(line):
    return hashlib.sha256(line.strip().encode()).hexdigest()
