import math
import os.path
import shutil
import sys
from collections import namedtuple
from typing import Iterable

import numpy as np
from bloom_filter2 import BloomFilter
from loguru import logger
from matplotlib import pyplot as plt
from sklearn.metrics import precision_recall_curve, det_curve, average_precision_score
from tqdm import tqdm
from tqdm.contrib import tzip

ThresholdInfo = namedtuple("ThresholdInfo", "recall tnr")


def get_require_threshold(threshold_info, require_recall=0.95):
    target_threshold, recall, tnr = math.inf, 1, 0
    t = sorted(threshold_info.items(), key=lambda x: x[0])
    for threshold, info in t:
        if info["recall"] >= require_recall:
            target_threshold = threshold
        else:
            break
    return target_threshold


def _query_similarity(cnt):
    return -cnt


class SFBL:
    def __init__(self, n, N=10000, maximum_tries=100, dropout_rate=0.1, seed=20231031, rebuild=False, use_cache=True):
        self.cache_dir = "cache/sfbl"
        self._max_workers = 10
        self._threshold = -(maximum_tries - 1)  # default threshold related to maximum_tries
        self._dropout_cnt = round(n * dropout_rate)
        self._maximum_tries = maximum_tries
        self.rebuild = rebuild
        if use_cache:
            if not os.path.exists(self.cache_dir) or len(os.listdir(self.cache_dir)) != self._maximum_tries:
                self.rebuild = True
                shutil.rmtree(self.cache_dir, ignore_errors=True)
                os.makedirs(self.cache_dir)
            self._filters = [BloomFilter(max_elements=N, error_rate=1e-5,
                                         filename=(os.path.join(self.cache_dir, f"{i}.sfbl.bin"), -1),
                                         start_fresh=self.rebuild) for i in range(self._maximum_tries)]
        else:
            self._filters = [BloomFilter(max_elements=N, error_rate=1e-5) for _ in range(self._maximum_tries)]
        self._seed = seed

    def _vector_encode(self, vector: np.ndarray):
        return vector[self._dropout_cnt:].tobytes()

    def insert(self, vector: np.ndarray):
        t = vector.copy()
        for i in range(self._maximum_tries):
            rng = np.random.RandomState(self._seed + i)
            rng.shuffle(t)
            self._filters[i].add(self._vector_encode(t))

    def query(self, vector: np.ndarray):
        t = vector.copy()
        for i in range(self._maximum_tries):
            rng = np.random.RandomState(self._seed + i)
            rng.shuffle(t)
            if self._vector_encode(t) in self._filters[i]:
                return _query_similarity(i)
        return _query_similarity(self._maximum_tries)

    def find_threshold(self, construct_vec: Iterable[np.ndarray],
                       target_vec: Iterable[np.ndarray], target_tags: Iterable[int],
                       require_recall=0.99,
                       print_all_threshold=False,
                       draw_pr_curve=False, pr_curve_filename="PRC.tif") -> int:

        score_list = []
        tags = []

        for v in tqdm(construct_vec, desc="Construct Set", unit="Funcs", smoothing=0, file=sys.stdout):
            self.insert(v)

        for v, tag in tzip(target_vec, target_tags, desc="Query Set", unit="Funcs", smoothing=0, file=sys.stdout):
            score = self.query(v)
            score_list.append(score)
            tags.append(tag)

        precision, recall, threshold = precision_recall_curve(tags, score_list)
        threshold_info = {}
        for p, r, t in zip(precision, recall, threshold):
            threshold_info[t] = {"recall": r, "tnr": -1}
        fpr, fnr, threshold = det_curve(tags, score_list)
        for fp, fn, t in zip(fpr, fnr, threshold):
            threshold_info[t]["tnr"] = 1 - fp

        if draw_pr_curve:
            plt.plot(recall, precision, lw=2,
                     label='PR (area = %0.2f)' % average_precision_score(tags, score_list))
            fontsize = 14
            plt.xlabel('Recall', fontsize=fontsize)
            plt.ylabel('Precision', fontsize=fontsize)
            plt.title('Precision Recall Curve')
            plt.legend()
            plt.savefig(pr_curve_filename, dpi=300)

        if print_all_threshold:
            for threshold in threshold_info:
                logger.debug("Threshold {:.3f}：Recall：{:.3f}，TNR：{:.3f}".format(threshold,
                                                                                threshold_info[threshold]["recall"],
                                                                                threshold_info[threshold]["tnr"]))
        return get_require_threshold(threshold_info, require_recall)

    def construct(self, construct_vec: Iterable[np.ndarray], threshold: float) -> None:
        if not self.rebuild:
            logger.critical("Constructing a constructed SFBL")
            raise Exception("Constructing a constructed SFBL")
        self._threshold = threshold
        for v in tqdm(construct_vec, desc="Construct Set", unit="Funcs", smoothing=0, file=sys.stdout):
            self.insert(v)

    def detect(self, target_vec: np.ndarray) -> bool:
        score = self.query(target_vec)  # the score is a negative. The less similar, the fewer score.
        return score > self._threshold
