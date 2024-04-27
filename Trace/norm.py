import os
import re
import subprocess
import sys

from .utils import TRACE_DIR


ctags = f"{TRACE_DIR}/../Preprocessor/universal-ctags/ctags"


def abstract(function):
    tmp = "./temp.cpp"
    with open(tmp, "w", encoding="UTF-8") as f:
        f.write(function)

    abstractBody = abstract_file(tmp, function)
    os.remove(tmp)
    return abstractBody


def abstract_file(file, function=None):
    if function is None:
        with open(file, "r") as f:
            function = f.read()

    abstract_func = function

    """
    ref: `--kinds-C++` : `ctags  --list-kinds-full | grep C++`
         f      function
         l      local
         v      variable
         z      parameter
    """
    command = f'{ctags} -f - --kinds-C++=flvz -u --fields=neKSt --language-force=c --language-force=c++ "{file}"'
    try:
        func_info = subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True
        ).decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        func_info = ""

    variables = []
    parameters = []

    funcs = func_info.split("\n")
    local_reg = re.compile(r"local")
    parameter_reg = re.compile(r"parameter")
    function_reg = re.compile(r"(function)")
    # param_space = re.compile(r"\(\s*([^)]+?)\s*\)")
    # word = re.compile(r"\w+")
    datatype_reg = re.compile(r"(typeref:)\w*(:)")
    number_reg = re.compile(r"(\d+)")
    # func_body = re.compile(r"{([\S\s]*)}")

    lines = []

    param_names = []
    dtype_names = []
    lvar_names = []

    for func in funcs:
        elements = re.sub(r"[\t\s ]{2,}", "", func)
        elements = elements.split("\t")
        if (
            func != ""
            and len(elements) >= 6
            and (local_reg.fullmatch(elements[3]) or local_reg.fullmatch(elements[4]))
        ):
            variables.append(elements)

        if (
            func != ""
            and len(elements) >= 6
            and (
                parameter_reg.match(elements[3]) or parameter_reg.fullmatch(elements[4])
            )
        ):
            parameters.append(elements)

    
    for func in funcs:
        elements = re.sub(r"[\t\s ]{2,}", "", func)
        elements = elements.split("\t")
        if func != "" and len(elements) >= 8 and function_reg.fullmatch(elements[3]):
            lines = (
                int(number_reg.search(elements[4]).group(0)),
                int(number_reg.search(elements[7]).group(0)),
            )

            # print (lines)

            line = 0
            for param_name in parameters:
                if number_reg.search(param_name[4]):
                    line = int(number_reg.search(param_name[4]).group(0))
                elif number_reg.search(param_name[5]):
                    line = int(number_reg.search(param_name[5]).group(0))
                if len(param_name) >= 4 and lines[0] <= int(line) <= lines[1]:
                    param_names.append(param_name[0])
                    if len(param_name) >= 6 and datatype_reg.search(param_name[5]):
                        dtype_names.append(
                            re.sub(r" \*$", "", datatype_reg.sub("", param_name[5]))
                        )
                    elif len(param_name) >= 7 and datatype_reg.search(param_name[6]):
                        dtype_names.append(
                            re.sub(r" \*$", "", datatype_reg.sub("", param_name[6]))
                        )

            for variable in variables:
                if number_reg.search(variable[4]):
                    line = int(number_reg.search(variable[4]).group(0))
                elif number_reg.search(variable[5]):
                    line = int(number_reg.search(variable[5]).group(0))
                if len(variable) >= 4 and lines[0] <= int(line) <= lines[1]:
                    lvar_names.append(variable[0])
                    if len(variable) >= 6 and datatype_reg.search(variable[5]):
                        dtype_names.append(
                            re.sub(r" \*$", "", datatype_reg.sub("", variable[5]))
                        )
                    elif len(variable) >= 7 and datatype_reg.search(variable[6]):
                        dtype_names.append(
                            re.sub(r" \*$", "", datatype_reg.sub("", variable[6]))
                        )

    
    try:
        param_id = 0
        for param_name in param_names:
            if len(param_name) == 0:
                continue
            paramPattern = re.compile("(^|\W)" + param_name + "(\W)")
            abstract_func = paramPattern.sub(
                f"\g<1>FPARAM{param_id}\g<2>", abstract_func
            )
            param_id += 1

        dtype_id = 0
        for dtype in dtype_names:
            if len(dtype) == 0:
                continue
            dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
            abstract_func = dtypePattern.sub(
                f"\g<1>DTYPE{dtype_id}\g<2>", abstract_func
            )
            dtype_id += 1

        lvar_id = 0
        for lvar in lvar_names:
            if len(lvar) == 0:
                continue
            lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
            abstract_func = lvarPattern.sub(f"\g<1>LVAR{lvar_id}\g<2>", abstract_func)
            lvar_id += 1

    except:  # noqa: E722
        pass

    return abstract_func


def norm(code):
    code = re.sub("(?<!:)\\/\\/.*|\\/\\*(\\s|.)*?\\*\\/", "", code)
    # code = "\n".join(clean_gadget(code.splitlines()))

    return code


def norm_i2o(i, o):
    with open(i, "r") as fi:
        code = fi.read()
        code = norm(code)
        with open(o, "w") as fo:
            fo.write(code)


if __name__ == "__main__":
    # norm_i2o(sys.argv[1], sys.argv[2])
    print(abstract_file(sys.argv[1]))
