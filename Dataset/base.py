import abc
from typing import List


class BaseDataset:
    def __init__(self, dataset_folder_path: str, seed=20231031):
        """
        Initialize basic property of the Dataset
        :param dataset_folder_path: Path to the folder of Dataset
        :param seed: seed for random
        """
        self.dataset_folder_path = dataset_folder_path
        self.seed = seed

    @abc.abstractmethod
    def get_funcs(self, size=-1, **kwargs) -> List[str]:
        return []
