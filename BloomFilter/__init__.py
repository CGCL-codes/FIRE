from typing import List

from loguru import logger

import BloomFilter.main


def initialization(
        vul_functions_sample: List[str],
        vul_functions_no_sample: List[str],
        no_vul_functions: List[str],
        sfbl_dropout_rate=0.17,
        require_recall=0.96,
        rebuild=False
) -> None:
    logger.info("Initialize BloomFilter")
    BloomFilter.main.initialization(
        vul_functions_sample,
        vul_functions_no_sample,
        no_vul_functions,
        sfbl_dropout_rate,
        require_recall,
        rebuild
    )
    logger.info("BloomFilter Initialized")


def detect(input_queue, output_queue, pbar_queue) -> None:
    while True:
        vul_info = input_queue.get()
        if vul_info[1] == "__end_of_detection__":
            output_queue.put(vul_info)
            logger.info("Bloom Filter Finished!")
            return
        function, function_path = vul_info
        is_vul = BloomFilter.main.detect(function)
        pbar_queue.put(("bloom", is_vul))
        if is_vul:
            # logger.debug(
            #     f"BloomFilter: Found potential vulnerable function in {function_path}"
            # )
            output_queue.put((function, function_path, []))
