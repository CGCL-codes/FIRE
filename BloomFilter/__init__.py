from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List

from loguru import logger

import BloomFilter.main
import config


def initialization(vul_functions: List[str], rebuild=False) -> None:
    logger.info("Initialize BloomFilter")
    BloomFilter.main.initialization(vul_functions, rebuild)
    logger.info("BloomFilter Initialized")


def detect(input_queue, output_queue, pbar_queue) -> None:
    with ProcessPoolExecutor(max_workers=config.bloom_filter_worker) as executor:
        futures = {}

        def process_future(future):
            is_vul = future.result()
            pbar_queue.put(("bloom", is_vul))
            if is_vul:
                function, function_path = futures[future]
                output_queue.put((function, function_path, []))

        while True:
            vul_info = input_queue.get()

            if vul_info[1] == "__end_of_detection__":
                for future in as_completed(futures.keys()):
                    process_future(future)
                output_queue.put(vul_info)
                logger.info("Bloom Filter Finished!")
                return

            function, function_path, _ = vul_info

            future = executor.submit(BloomFilter.main.detect, function)
            futures[future] = (function, function_path)

            done_futures = []

            for future in futures.keys():
                if not future.done():
                    continue
                process_future(future)
                done_futures.append(future)

            for future in done_futures:
                futures.pop(future)


from .feature_extractor import FeatureExtractor
