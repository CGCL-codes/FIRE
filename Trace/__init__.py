from concurrent.futures import ProcessPoolExecutor, as_completed
from loguru import logger

import config
from .detection import detect_vulnerable_with_initialize
from .utils import vuln_to_patch_dict

def initialization(file_pair_list):
    logger.info("Initialize Trace")
    for vuln_file, patch_file in file_pair_list:
        vuln_to_patch_dict[vuln_file] = patch_file
    return


def detect(
    input_queue,
    output_queue,
    pbar_queue,
    trace_all_result_queue = None
) -> None:
    with ProcessPoolExecutor(max_workers=config.trace_worker) as executor:
        futures = {}

        def process_future(future):
            try:
                is_vul, similar_list = future.result()
            except Exception as e:
                pbar_queue.put(("trace", False))
                logger.error(f"{str(e)}")
            else:
                pbar_queue.put(("trace", is_vul))
                if not is_vul:
                    return
                dst_func, dst_file = futures[future]
                output_queue.put((dst_func, dst_file, similar_list))
                logger.debug(f"Trace: Found potential vulnerable function in {dst_file}")

        while True:
            vul_info = input_queue.get()
            dst_func, dst_file, similar_list = vul_info

            if dst_file == "__end_of_detection__":
                for future in as_completed(futures.keys()):
                    process_future(future)
                output_queue.put(vul_info)
                pbar_queue.put(("__end_of_detection__", False))

                if trace_all_result_queue:
                    trace_all_result_queue.put(0)
                logger.info("Trace Finished!")
                break

            future = executor.submit(
                detect_vulnerable_with_initialize, dst_func, dst_file, similar_list, trace_all_result_queue
            )
            futures[future] = (dst_func, dst_file)

            done_futures = []
            for future in futures.keys():
                if not future.done():
                    continue
                process_future(future)
                done_futures.append(future)

            for future in done_futures:
                futures.pop(future)

                
