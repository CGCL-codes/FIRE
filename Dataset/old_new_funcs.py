# OldNewFuncsDataset Folder
# Main Folder - Software - CVE - sample functions(OLD=vul NEW=no vul)
import os.path
import random
import shutil
import sys
from collections import namedtuple
from typing import List, Tuple

from loguru import logger
from tqdm import tqdm

import Dataset.base
import Dataset.utils
from Dataset.utils import abs_listdir, function_purification


def old_new_funcs_filename_split(name: str) -> (str, str, str, str, str, str, str):
    """
    A util function to parse the filename of old new funcs
    :param name: the filename to parse
    :return: Corresponding CVE, CWE, commit_hash, filename, version, function name, vulnerable/patch
    """
    part = name.split("_")
    cve = part[0]
    cwe = part[1]
    commit_hash = part[2]
    # filename
    i = 3
    # All the filename in old_new_funcs contains any .c
    while part[i].rfind(".c") != -1:
        i += 1
    file_name = "_".join(part[3:i])
    if part[i].rfind(".") != -1:
        version = part[i]
        i += 1
    else:
        version = ""
    func_name = "_".join(part[i:-1])
    old_new = part[-1][:-4]
    return (cve.strip(), cwe.strip(), commit_hash.strip(), file_name.strip(), version.strip(), func_name.strip(),
            old_new.strip())


class OldNewFuncsDataset(Dataset.base.BaseDataset):
    FunctionInfo = namedtuple("FunctionInfo", "software cve function_name vul sample")

    def _software_path(self, software):
        return os.path.join(self.dataset_folder_path, software)

    def _cve_path(self, software, cve):
        return os.path.join(self._software_path(software), cve)

    def _function_path(self, software, cve, function):
        return os.path.join(self._cve_path(software, cve), function)

    def _software_list_generator(self):
        return filter(lambda software: os.path.isdir(self._software_path(software)),
                      os.listdir(self.dataset_folder_path))

    def _cve_list_generator(self, software):
        return filter(lambda cve: os.path.isdir(self._cve_path(software, cve)),
                      os.listdir(self._software_path(software)))

    def _function_list_generator(self, software, cve):
        return os.listdir(self._cve_path(software, cve))

    def _preprocess(self):
        logger.info("Preprocessing Old_New_Funcs Dataset")
        with tqdm(desc="Old_New_Funcs", unit="Funcs", file=sys.stdout) as pbar:
            for software in self._software_list_generator():
                for cve in self._cve_list_generator(software):
                    function_set = set()
                    for function in self._function_list_generator(software, cve):
                        func_path = self._function_path(software, cve, function)
                        with open(func_path) as f:
                            # Code Purification
                            try:
                                raw_code = f.read()
                            except UnicodeDecodeError:
                                with open(func_path, encoding="cp1252") as f2:
                                    raw_code = str(f2.read())
                            code = function_purification(raw_code)
                        if code == "":
                            continue
                        # Function Tagging
                        _, _, _, _, _, func_name, old_new = old_new_funcs_filename_split(function)
                        # OLD function are vulnerable function
                        # while NEW function are patched function of the corresponding OLD function
                        is_vul = (old_new == "OLD")
                        if is_vul:
                            if func_name not in function_set:
                                target_file = os.path.join(self.sample_dir, function)
                                function_set.add(func_name)
                            else:
                                target_file = os.path.join(self.non_sample_dir, function)
                        else:
                            target_file = os.path.join(self.no_vul_dir, function)
                        pbar.update()
                        with open(target_file, "w") as f:
                            f.write(code)
        logger.info("Preprocessing Finished")

    def __init__(self, dataset_folder_path, seed=20231031, rebuild=False):
        """
        Initializing the Old New Funcs Dataset
        :param dataset_folder_path: Where the dataset stores
        :param seed: seed for random
        """
        super().__init__(dataset_folder_path, seed)
        self.dataset_folder_path = dataset_folder_path
        self.seed = seed
        self.funcs_info = {}

        logger.info("Initializing Old_New_Funcs Dataset")
        self.cache_dir = os.path.join(os.getcwd(), "cache", "old_new_funcs")
        self.vul_dir = os.path.join(self.cache_dir, "vul")
        self.no_vul_dir = os.path.join(self.cache_dir, "no_vul")
        self.sample_dir = os.path.join(self.vul_dir, "sample")
        self.non_sample_dir = os.path.join(self.vul_dir, "non_sample")
        for chk_dir in [self.sample_dir, self.non_sample_dir, self.no_vul_dir]:
            if rebuild or not (os.path.exists(chk_dir) and len(os.listdir(chk_dir)) != 0):
                shutil.rmtree(self.cache_dir, ignore_errors=True)
                os.makedirs(self.sample_dir, exist_ok=True)
                os.makedirs(self.non_sample_dir, exist_ok=True)
                os.makedirs(self.no_vul_dir, exist_ok=True)
                self._preprocess()
                break
        else:
            logger.info("Using Old_New_Funcs preprocessed Cache")
        sample_size = len(os.listdir(self.sample_dir))
        non_sample_size = len(os.listdir(self.non_sample_dir))
        no_vul_size = len(os.listdir(self.no_vul_dir))
        logger.info(f"Old_New_Funcs Dataset Total Size {sample_size + non_sample_size + no_vul_size}")
        logger.info(f"VulFunctions: {sample_size + non_sample_size}, VulSamples: {sample_size}")
        logger.info(f"NoVulFunctions: {no_vul_size}")

    def get_funcs(self, size=-1, vul=False, no_vul=False, sample=False, non_sample=False) -> List[str]:
        """
        Get the function list of the OLD NEW FUNCS dataset.
        Only one True among : vul no_vul sample non_sample
        vul = sample + non_sample
        whole_dataset = vul + no_vul
        :param size: Size of the return function list
        :param vul: All the return function list is vulnerable
        :param no_vul: All the return function list is not vulnerable
        :param sample: All the return function list is vulnerable and contains no duplicate source function.(No function
        has another vulnerable version in the list)
        :param non_sample: The function which vulnerable but not in the sample list
        :return: the function path list
        """
        if vul:
            func_path_list = abs_listdir(self.sample_dir) + abs_listdir(self.non_sample_dir)
        elif no_vul:
            func_path_list = abs_listdir(self.no_vul_dir)
        elif sample:
            func_path_list = abs_listdir(self.sample_dir)
        elif non_sample:
            func_path_list = abs_listdir(self.non_sample_dir)
        else:
            func_path_list = (abs_listdir(self.sample_dir) + abs_listdir(self.non_sample_dir) +
                              abs_listdir(self.no_vul_dir))

        if size != -1:
            rng = random.Random(self.seed)
            func_path_list = rng.sample(func_path_list, min(size, len(func_path_list)))

        return func_path_list

    def get_func_pairs(self) -> List[Tuple[str, str]]:
        """
        Output old and new function pairs
        :return: function pair list
        """
        func_pairs = []

        def _find_func_pairs(target_dir):
            sample_list = os.listdir(target_dir)
            for func_rel_path in sample_list:
                new_func_rel_path = func_rel_path.replace("OLD", "NEW")
                if os.path.exists(os.path.join(self.no_vul_dir, new_func_rel_path)):
                    func_pairs.append((os.path.join(target_dir, func_rel_path),
                                       os.path.join(self.no_vul_dir, new_func_rel_path)))

        _find_func_pairs(self.sample_dir)
        _find_func_pairs(self.non_sample_dir)
        return func_pairs
