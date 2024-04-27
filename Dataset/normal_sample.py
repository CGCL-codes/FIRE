import os
import random
import shutil
import sys
from typing import List

from loguru import logger
from tqdm import tqdm

import Dataset.base
import Dataset.utils


class NormalSampleDataset(Dataset.base.BaseDataset):
    def _software_path(self, software):
        return os.path.join(self.dataset_folder_path, software)

    def _function_path(self, software, function):
        return os.path.join(self._software_path(software), function)

    def _software_list_generator(self):
        def _is_dir(software):
            return os.path.isdir(self._software_path(software))

        return filter(_is_dir, os.listdir(self.dataset_folder_path))

    def _function_list_generator(self, software):
        return os.listdir(self._software_path(software))

    def _preprocess(self, size, seed):
        logger.info("Preprocessing NormalSample Dataset")
        func_path_list = []
        for software in self._software_list_generator():
            for function in self._function_list_generator(software):
                func_path_list.append((function, self._function_path(software, function)))
        rng = random.Random(seed)
        rng.shuffle(func_path_list)
        i = 0
        with tqdm(total=size, desc="Normal", unit="Funcs", file=sys.stdout) as pbar:
            for function, func_path in func_path_list:
                with open(func_path) as f:
                    code = Dataset.utils.function_purification(f.read())
                if code == "":
                    continue
                target_file = os.path.join(self.cache_dir, function)
                with open(target_file, "w") as f:
                    f.write(code)
                i += 1
                pbar.update()
                if i == size:
                    break
        logger.info("Preprocessing Finished")

    def __init__(self, dataset_folder_path: str, seed=20231031, size=3000, rebuild=False):
        """
        Initialize NormalSample dataset
        :param dataset_folder_path: Path to the folder of NormalSample Dataset
        :param seed: seed for random
        """
        super().__init__(dataset_folder_path, seed)

        logger.info("Initializing NormalSample Dataset")
        self.cache_dir = os.path.join(os.getcwd(), "cache", "normal")
        if rebuild or not (os.path.exists(self.cache_dir) and len(os.listdir(self.cache_dir)) == size):
            shutil.rmtree(self.cache_dir, ignore_errors=True)
            os.makedirs(self.cache_dir, exist_ok=True)
            self._preprocess(size, self.seed)
        else:
            logger.info("Using NormalSample preprocessed Cache")
        logger.info(f"NormalSample Dataset Size: {len(os.listdir(self.cache_dir))}")

    def get_funcs(self, **kwargs) -> (List[str], List[int]):
        """
        Get the function list of the NormalSample dataset.
        :return: The function list & The tag.
        """
        return Dataset.utils.abs_listdir(self.cache_dir)
