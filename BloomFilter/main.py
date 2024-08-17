import json
import os

import numpy as np
from loguru import logger

import BloomFilter.sfbl
import BloomFilter.feature_extractor

DetectFilter = None


def _threshold_to_maximum_tries(threshold: int) -> int:
    return -threshold + 1


def _default_dump(obj):
    """Convert numpy classes to JSON serializable objects."""
    if isinstance(obj, (np.integer, np.floating, np.bool_)):
        return obj.item()
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj


def initialization(vul_functions, rebuild=False):
    cache_json_path = "cache/bloomFilter.json"
    Extractor = BloomFilter.feature_extractor.FeatureExtractor()
    try:
        if rebuild:
            raise Exception("Rebuild flag on")
        with open(cache_json_path) as f:
            threshold = json.load(f)["threshold"]
    except Exception as e:
        rebuild = True
        logger.warning("Threshold cache fail or rebuild flag on, refind threshold: {}".format(e))
        threshold = -100
        # For convenience generating SFBF, the procedure of generating threshold is removed and the value of threshold
        # is fixed to -100(100 tries).
        #
        # non_sample, normal_dataset is no need here anymore. You can just use vulnerability functions you collected
        # to generate the SFBF with the corresponding format listed in the README.
        #
        # If you want to know how we set the threshold to -100, please refer to the previous commit.
        #
        # To find out the threshold, you should prepare a vulnerable function dataset which have different
        # versions of vulnerable, a normal dataset which consist functions of popular projects.
        os.makedirs(os.path.dirname(cache_json_path), exist_ok=True)
        with open(cache_json_path, "w") as f:
            json.dump({"threshold": threshold}, f, default=_default_dump)
    logger.info(f"Bloom Filter Using Threshold: {threshold}")
    # SFBL Bloom Filter Constructing
    global DetectFilter
    DetectFilter = BloomFilter.sfbl.SFBL(n=Extractor.n, maximum_tries=_threshold_to_maximum_tries(threshold),
                                         dropout_rate=0.17, rebuild=rebuild)
    if DetectFilter.rebuild:
        construct_vectors = Extractor.extract_from_files(vul_functions)
        DetectFilter.construct(construct_vectors, threshold)
    else:
        logger.info("Using Cached Bloom Filter Bins")


def detect(code: str) -> bool:
    if isinstance(DetectFilter, BloomFilter.sfbl.SFBL):
        Extractor = BloomFilter.feature_extractor.FeatureExtractor()
        vector = Extractor.extract_vector(code)
        return DetectFilter.detect(vector)
    else:
        logger.critical("Bloom Filter Not Initialized")
        raise Exception("Bloom Filter Not Initialized")
