import json
import os

import numpy as np
from loguru import logger

import BloomFilter.sfbl
import BloomFilter.feature_extractor

Extractor = BloomFilter.feature_extractor.FeatureExtractor()
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


def initialization(vul_functions_sample, vul_functions_no_sample, no_vul_functions, sfbl_dropout_rate=0.17,
                   require_recall=0.96, rebuild=False):
    cache_json_path = "cache/bloomFilter.json"
    try:
        if rebuild:
            raise Exception("Rebuild flag on")
        with open(cache_json_path) as f:
            threshold = json.load(f)["threshold"]
    except Exception as e:
        rebuild = True
        logger.warning("Threshold cache fail or rebuild flag on, refind threshold: {}".format(e))
        # Find Threshold Parse
        construct_set = vul_functions_sample
        construct_vectors = Extractor.extract_from_files(construct_set)
        target_set = [*vul_functions_no_sample, *no_vul_functions]
        target_vector = Extractor.extract_from_files(target_set)
        target_tags = [1] * len(vul_functions_no_sample) + [0] * len(no_vul_functions)
        sfbl_filter = BloomFilter.sfbl.SFBL(n=Extractor.n, maximum_tries=100, dropout_rate=sfbl_dropout_rate,
                                            use_cache=False)
        threshold = sfbl_filter.find_threshold(construct_vectors, target_vector, target_tags,
                                               require_recall=require_recall)
        os.makedirs(os.path.dirname(cache_json_path), exist_ok=True)
        with open(cache_json_path, "w") as f:
            json.dump({"threshold": threshold}, f, default=_default_dump)
    logger.info(f"Bloom Filter Using Threshold: {threshold}")
    # SFBL Bloom Filter Constructing
    global DetectFilter
    DetectFilter = BloomFilter.sfbl.SFBL(n=Extractor.n, maximum_tries=_threshold_to_maximum_tries(threshold),
                                         dropout_rate=sfbl_dropout_rate, rebuild=rebuild)
    if DetectFilter.rebuild:
        construct_set = [*vul_functions_sample, *vul_functions_no_sample]
        construct_vectors = Extractor.extract_from_files(construct_set)
        DetectFilter.construct(construct_vectors, threshold)
    else:
        logger.info("Using Cached Bloom Filter Bins")


def detect(code: str) -> bool:
    if isinstance(DetectFilter, BloomFilter.sfbl.SFBL):
        vector = Extractor.extract_vector(code)
        return DetectFilter.detect(vector)
    else:
        logger.critical("Bloom Filter Not Initialized")
        raise Exception("Bloom Filter Not Initialized")
