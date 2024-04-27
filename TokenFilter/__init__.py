from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List

from loguru import logger

import TokenFilter.main


def initialization(vul_functions: List[str]) -> None:

    logger.info("Initialize TokenFilter")
    TokenFilter.main.initialization(vul_functions)
    logger.info("TokenFilter Initialized")


def detect(input_queue, output_queue, pbar_queue) -> None:
    with ProcessPoolExecutor(max_workers=20) as executor:
        futures = {}
        
        def process_future(future):
            is_vul, similar_list = future.result()
            pbar_queue.put(("token", is_vul))
            if not is_vul:
                return
            dst_func, dst_file = futures[future]
            output_queue.put((dst_func, dst_file, similar_list))
            # logger.debug(f"TokenFilter: Found potential vulnerable function in {dst_file}")
            
        while True:      
            vul_info = input_queue.get()
            dst_func, dst_file, _ = vul_info

            
            try:
                if dst_file == "__end_of_detection__":
                    for future in as_completed(futures.keys()):
                        process_future(future)
                    output_queue.put(vul_info)
                    logger.info("Token Filter Finished!")
                    return

                future = executor.submit(TokenFilter.main.detect, dst_func)
                futures[future] = (dst_func, dst_file)

                done_futures = []
            
                for future in futures.keys():
                    if not future.done():
                        continue
                    process_future(future)
                    done_futures.append(future)

                for future in done_futures:
                    futures.pop(future)

            except Exception as e:
                logger.error(f"Error detect in {dst_file}: {str(e)}")
    
