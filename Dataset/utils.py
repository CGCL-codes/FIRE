import os
import re


def function_purification(code: str, skip_loc_threshold=False) -> str:
    # remove comments
    code = re.sub('\/\*[\w\W]*?\*\/', "", code)
    code = re.sub(r'//.*?\n', "\n", code)
    # remove non-ASCII
    code = re.sub(r"[^\x00-\x7F]+", "", code)
    # remove #
    code = re.sub(r"^#.*", "", code, flags=re.MULTILINE)
    # Counting ; as a way to see how many code lines, We do not consider very short functions
    if not skip_loc_threshold and code.count(";") <= 3:
        return ""
    # remove the empty line to compact the code
    purified_code_lines = list(filter(lambda c: len(c.strip()) != 0, code.split("\n")))
    # Counting the line which blank or contain only 1 char, We do not consider very short functions
    loc = 0
    for i in range(len(purified_code_lines)):
        purified_code_lines[i] = purified_code_lines[i].strip()
        loc += 1 if len(purified_code_lines[i]) > 1 else 0
    if not skip_loc_threshold and loc <= 5:
        return ""
    return "\n".join(purified_code_lines)


def abs_listdir(directory: str):
    return [os.path.join(directory, path) for path in os.listdir(directory)]
