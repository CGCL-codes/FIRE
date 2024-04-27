import copy
import re
import threading
from typing import List, Iterable

import numpy as np
# noinspection PyUnresolvedReferences
from pygments.lexers.c_cpp import CppLexer
from pygments.token import Token


class OperatorStateMachine:
    _Operators = frozenset(['++', '--', '+', '-', '*', '/', '%', '=', '+=', '-=', '*=', '/=', '%=', '<<=',
                            '>>=', '&=', '^=', '|=', '&&', '||', '!', '==', '!=', '>=', '<=', '>', '<', '&',
                            '|', '<<', '>>', '~', '^', '->'])  # 42
    _double_operator = frozenset(["&", "+", "-", "|"])
    _double_operator2 = frozenset(["<", ">"])

    def __init__(self):
        self.current_state = ""

    def clear(self):
        self.current_state = ""

    def process(self, current=None):
        if current is None and self.current_state != "":
            op = self.current_state
            self.current_state = ""
            return op
        if len(self.current_state) == 0:
            if current == "~":
                return "~"
            if current in self._Operators:
                self.current_state += current
                return None
        elif len(self.current_state) == 1:
            op = self.current_state + current
            if current == "=":
                self.current_state = ""
                return op
            elif current == self.current_state:
                if current in self._double_operator:  # && ++ -- ||
                    self.current_state = ""
                    return op
                if current in self._double_operator2:  # << >> may go to <<= and >>=
                    self.current_state = op
                    return None
                else:
                    op = self.current_state
                    self.current_state = current
                    return op
            elif op == "->":
                self.current_state = ""
                return "->"
            else:
                op = self.current_state
                self.current_state = current
                return op
        else:
            op = self.current_state + current
            if current == "=":  # only <<= and >>=
                self.current_state = ""
                return op
            else:
                op = self.current_state
                self.current_state = current
                return op
        return None


class FeatureExtractor:
    _APIs = ['alloc', 'free', 'mem', 'copy', 'new', 'open', 'close', 'delete', 'create', 'release',
             'sizeof', 'remove', 'clear', 'dequene', 'enquene', 'detach', 'Attach', 'str', 'string',
             'lock', 'mutex', 'spin', 'init', 'register', 'disable', 'enable', 'put', 'get', 'up',
             'down', 'inc', 'dec', 'add', 'sub', 'set', 'map', 'stop', 'start', 'prepare', 'suspend',
             'resume', 'connect']  # 42

    _Formatted_strings = ['d', 'i', 'o', 'u', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G',
                          'a', 'A', 'c', 'C', 's', 'S', 'p', 'n']  # 21

    _Operators = ['bitand', 'bitor', 'xor', 'not', 'not_eq', 'or', 'or_eq', 'and', '++', '--',
                  '+', '-', '*', '/', '%', '=', '+=', '-=', '*=', '/=', '%=', '<<=',
                  '>>=', '&=', '^=', '|=', '&&', '||', '!', '==', '!=', '>=', '<=', '>', '<', '&',
                  '|', '<<', '>>', '~', '^', '->']  # 42

    _Keywords = ['asm', 'auto', 'alignas', 'alignof', 'bool', 'break', 'case',
                 'catch', 'char', 'char16_t', 'char32_t', 'class', 'const', 'const_cast',
                 'constexpr', 'continue', 'decltype', 'default', 'do', 'double',
                 'dynamic_cast', 'else', 'enum', 'explicit', 'export', 'extern', 'false', 'float',
                 'for', 'friend', 'goto', 'if', 'inline', 'int', 'long', 'mutable', 'namespace',
                 'noexcept', 'nullptr', 'operator', 'private', 'protected', 'public',
                 'reinterpret_cast', 'return', 'short', 'signed', 'static',
                 'static_assert', 'static_cast', 'struct', 'switch', 'template', 'this',
                 'thread_local', 'throw', 'true', 'try', 'typedef', 'typeid', 'typename', 'union',
                 'unsigned', 'using', 'virtual', 'void', 'volatile', 'wchar_t', 'while', 'compl',
                 'override', 'final', 'assert']  # 77

    def __init__(self):
        self._No_Formatted_string_List = self._APIs + self._Operators + self._Keywords
        self._No_Formatted_string_Dict = dict([word, 0] for word in self._No_Formatted_string_List)
        self._Formatted_strings_Dict = dict([word, 0] for word in self._Formatted_strings)
        self.lexer = CppLexer()
        self.operator_state_machine = OperatorStateMachine()
        self.n = len(self._No_Formatted_string_List) + len(self._Formatted_strings)
        self.lock = threading.Lock()

    def clean(self):
        self._No_Formatted_string_Dict = dict([word, 0] for word in self._No_Formatted_string_List)
        self._Formatted_strings_Dict = dict([word, 0] for word in self._Formatted_strings)
        self.lexer = CppLexer()
        self.operator_state_machine.clear()

    def _extract(self, code: str):
        tokens = self.lexer.get_tokens(code)
        for token_type, value in tokens:
            if token_type == Token.Operator:
                op = self.operator_state_machine.process(value)
                if op is not None:
                    if op in self._No_Formatted_string_List:
                        self._No_Formatted_string_Dict[op] += 1
            else:
                op = self.operator_state_machine.process()
                if op is not None:
                    if op in self._No_Formatted_string_List:
                        self._No_Formatted_string_Dict[op] += 1
                if token_type == Token.Literal.String:
                    if value != '"':
                        format_symbols = re.findall(r'%([-+0 #]{0,5}\d*(?:\.\d+)?)[lhL]?([diouxXfFeEgGaAcCsSpn])',
                                                    value)
                        for symbols in format_symbols:
                            if symbols[-1] in self._Formatted_strings:
                                self._Formatted_strings_Dict[symbols[-1]] += 1
                if token_type in [Token.Keyword, Token.Keyword.Type, Token.Keyword.Reserved,
                                  Token.Name, Token.Name.Builtin]:
                    if value in self._No_Formatted_string_Dict:
                        self._No_Formatted_string_Dict[value] += 1
        return {**self._Formatted_strings_Dict, **self._No_Formatted_string_Dict}

    def extract_vector(self, code: str):
        with self.lock:
            self.clean()
            token_dict = self._extract(code)
            # One-Hot Vector
            return np.array([1 if token_dict[key] > 0 else 0 for key in token_dict], dtype=np.uint8)

    def extract_from_files(self, file_list: List[str]) -> Iterable:
        return FeatureVectorFileListIter(self, file_list)


class FeatureVectorFileListIter(Iterable):
    def __init__(self, extractor: FeatureExtractor, file_list: List[str]):
        self.extractor = extractor
        self.len = len(file_list)
        self.file_list = iter(file_list)

    def __iter__(self):
        iter_list = copy.deepcopy(self.file_list)
        for func_path in iter_list:
            with open(func_path, "r") as f:
                yield self.extractor.extract_vector(f.read())

    def __len__(self):
        return self.len
