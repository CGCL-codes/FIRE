import argparse
import csv
import json
import os
import queue
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager

from loguru import logger
from tqdm import tqdm

import BloomFilter
import Dataset
import SyntaxFilter
import TokenFilter
import Trace
import config

logger.remove()
logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")


def progress_bar_process(total_cnt, pbar_queue, output_name="detect_info.json"):
    def get_time(info):
        if info["done"] >= info["input"]:
            return info["offset"]
        else:
            return info["offset"] + info["last"] - info["start"]

    def stop_timer(info):
        info["offset"] += time.perf_counter() - info["start"]
        info["start"] = time.perf_counter()
        info["last"] = info["start"]

    def start_timer(info):
        info["start"] = time.perf_counter()
        info["last"] = info["start"]

    def record_time(info):
        info["last"] = time.perf_counter()

    bloom_info = dict(input=0, done=0, offset=0.0, start=0.0, last=0.0)
    token_info = dict(input=0, done=0, offset=0.0, start=0.0, last=0.0)
    syntax_info = dict(input=0, done=0, offset=0.0, start=0.0, last=0.0)
    trace_info = dict(input=0, done=0, offset=0.0, start=0.0, last=0.0)
    vul_cnt = 0
    postfix_info = {}
    with tqdm(
        total=total_cnt,
        smoothing=0,
        unit="f",
        bar_format="{n_fmt}/{total_fmt}~{remaining}[{rate_fmt}{postfix}]",
        file=sys.stdout,
    ) as pbar:
        while True:
            try:
                info_from, status = pbar_queue.get(timeout=0.1)
            except queue.Empty:
                info_from, status = ("Nothing", False)
            if info_from == "__end_of_detection__":
                # dumping final infos
                with open(output_name, "w") as f:
                    json.dump(postfix_info, f)
                break
            elif info_from == "dataset":
                if bloom_info["input"] == bloom_info["done"]:
                    start_timer(bloom_info)
                bloom_info["input"] += 1
            elif info_from == "bloom":
                bloom_info["done"] += 1
                if bloom_info["input"] <= bloom_info["done"]:
                    stop_timer(bloom_info)
                record_time(bloom_info)
                if status:
                    if token_info["input"] == token_info["done"]:
                        start_timer(token_info)
                    token_info["input"] += 1
                else:
                    pbar.update()
            elif info_from == "token":
                token_info["done"] += 1
                if token_info["input"] <= token_info["done"]:
                    stop_timer(token_info)
                record_time(token_info)
                if status:
                    if syntax_info["input"] == syntax_info["done"]:
                        start_timer(syntax_info)
                    syntax_info["input"] += 1
                else:
                    pbar.update()
            elif info_from == "syntax":
                syntax_info["done"] += 1
                if syntax_info["input"] <= syntax_info["done"]:
                    stop_timer(syntax_info)
                record_time(syntax_info)
                if status:
                    if trace_info["input"] == trace_info["done"]:
                        start_timer(trace_info)
                    trace_info["input"] += 1
                else:
                    pbar.update()
            elif info_from == "trace":
                trace_info["done"] += 1
                if trace_info["input"] <= trace_info["done"]:
                    stop_timer(trace_info)
                record_time(trace_info)
                pbar.update()
                if status:
                    vul_cnt += 1
            elif info_from == "Nothing":
                pass
            else:
                logger.error("Unknown Source Components")
            bloom_fail_filter_rate = token_info["input"] / max(bloom_info["done"], 1)
            bloom_speed = bloom_info["done"] / max(get_time(bloom_info), 1e-3)
            token_fail_filter_rate = syntax_info["input"] / max(token_info["done"], 1)
            token_speed = token_info["done"] / max(get_time(token_info), 1e-3)
            syntax_fail_filter_rate = trace_info["input"] / max(syntax_info["done"], 1)
            syntax_speed = syntax_info["done"] / max(get_time(syntax_info), 1e-3)
            trace_speed = trace_info["done"] / max(get_time(trace_info), 1e3)
            postfix_info = {
                "bloom": "%d/%d(%.1f%%,%.1ff/s)"
                % (
                    bloom_info["done"],
                    bloom_info["input"],
                    100 * (1 - bloom_fail_filter_rate),
                    bloom_speed,
                ),
                "token": "%d/%d(%.1f%%,%.2f[%.2f]f/s)"
                % (
                    token_info["done"],
                    token_info["input"],
                    100 * (1 - token_fail_filter_rate),
                    token_speed,
                    bloom_fail_filter_rate * bloom_speed,
                ),
                "syntax": "%d/%d(%.1f%%,%.2f[%.2f]f/s)"
                % (
                    syntax_info["done"],
                    syntax_info["input"],
                    100 * (1 - syntax_fail_filter_rate),
                    syntax_speed,
                    token_fail_filter_rate * token_speed,
                ),
                "trace": "%d/%d(%d,%.1f[%.1f]f/h)"
                % (
                    trace_info["done"],
                    trace_info["input"],
                    vul_cnt,
                    3600 * trace_speed,
                    3600 * (syntax_fail_filter_rate * syntax_speed),
                ),
            }
            pbar.set_postfix(postfix_info)


def put_dataset_to_queue(dataset: Dataset.Base, output_queue, pbar_queue):
    # datasets = []
    for func_path in dataset.get_funcs():
        with open(func_path) as f:
            output_queue.put((f.read(), func_path))
            pbar_queue.put(("dataset", False))

    output_queue.put((None, "__end_of_detection__", []))
    # return datasets


def dump_trace_func(input_queue, output_name="trace.csv"):
    traces = []
    while True:
        trace = input_queue.get()
        if trace == 0:
            break
        traces.append(trace)

        with open(output_name, "w") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=[
                    "target_file",
                    "vuln_file",
                    "patch_file",
                    "datail",
                    "predict",
                ],
            )
            writer.writeheader()
            writer.writerows(traces)


def dump_vulnerable_func(input_queue, output_name="vuls.json"):
    vul_dict = {}

    vuls = []
    vul_cnt = 0
    vul_all = 0
    while True:
        _, dst_file, similar_list = input_queue.get()
        if dst_file == "__end_of_detection__":
            break
        vul_cnt += 1

        vuls.append({"id": vul_cnt, "dst": dst_file, "sim": similar_list})

        logger.success(f"[No. {vul_cnt}]Vul Detected in {dst_file}")
        logger.success("Similar to Vulnerability:")
        for exist_vul in similar_list:
            logger.success(exist_vul)
            vul_all += 1

        vul_dict["cnt"] = vul_cnt
        vul_dict['all'] = vul_all
        vul_dict["vul"] = vuls

        logger.info(f"Dumping vulnerable function info to {output_name}")
        with open(output_name, "w") as f:
            json.dump(vul_dict, f, indent=4)

    if vul_cnt == 0:
        vul_dict = {
            "cnt": vul_cnt,
            "all": vul_all,
            "vul": vuls
        }
        logger.info(f"Dumping vulnerable function info to {output_name}")
        with open(output_name, "w") as f:
            json.dump(vul_dict, f, indent=4)

    logger.info("Dump vulnerable function finished!")


def main(ProjectDataset: Dataset.Project, output_name, rebuild_list):
    OldNewFuncsDataset = Dataset.OldNewFuncs(
        config.old_new_func_dataset_path, rebuild=("old-new-funcs" in rebuild_list)
    )
    NormalSampleDataset = Dataset.NormalSample(
        config.normal_sample_dataset_path, size=3000, rebuild=("normal-sample" in rebuild_list)
    )

    logger.info("Start Initialization")

    BloomFilter.initialization(
        OldNewFuncsDataset.get_funcs(sample=True),
        OldNewFuncsDataset.get_funcs(non_sample=True),
        NormalSampleDataset.get_funcs(),
        rebuild=("bloomFilter" in rebuild_list),
    )
    TokenFilter.initialization(OldNewFuncsDataset.get_funcs(vul=True))
    SyntaxFilter.initialization(OldNewFuncsDataset.get_func_pairs())
    Trace.initialization(OldNewFuncsDataset.get_func_pairs())

    manager = Manager()
    dataset_queue = manager.Queue(maxsize=100)
    pbar_queue = manager.Queue(maxsize=100)
    bloom_filter_processed_queue = manager.Queue(maxsize=2000)
    token_filter_processed_queue = manager.Queue(maxsize=1000)
    syntax_filter_processed_queue = manager.Queue(maxsize=100)
    vulnerable_func_queue = manager.Queue(maxsize=100)
    trace_all_result_queue = manager.Queue(maxsize=100)

    logger.info("Start Detection")


    with ProcessPoolExecutor(max_workers=8) as executor:
       
        futures = [
            executor.submit(
                progress_bar_process,
                len(ProjectDataset.get_funcs()),
                pbar_queue,
                os.path.splitext(output_name)[0] + ".detect_info.json",
            ),
            executor.submit(
                put_dataset_to_queue, ProjectDataset, dataset_queue, pbar_queue
            ),
            executor.submit(
                BloomFilter.detect,
                dataset_queue,
                bloom_filter_processed_queue,
                pbar_queue,
            ),
            executor.submit(
                TokenFilter.detect,
                bloom_filter_processed_queue,
                token_filter_processed_queue,
                pbar_queue,
            ),
            executor.submit(
                SyntaxFilter.detect,
                token_filter_processed_queue,
                syntax_filter_processed_queue,
                vulnerable_func_queue,
                pbar_queue,
                trace_all_result_queue,
            ),
            executor.submit(
                Trace.detect,
                syntax_filter_processed_queue,
                vulnerable_func_queue,
                pbar_queue,
                trace_all_result_queue,
            ),
            executor.submit(dump_vulnerable_func, vulnerable_func_queue, output_name),
            executor.submit(
                dump_trace_func,
                trace_all_result_queue,
                os.path.splitext(output_name)[0] + ".trace.csv",
            ),
        ]

      
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(e)

    logger.info("Detection Complete")

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract data from project dir")
    parser.add_argument("project", type=str, help="Path to the project dir")
    parser.add_argument("--rebuild", nargs="*", default=["target"],
                        choices=["bloomFilter", "old-new-funcs", "normal-sample", "target"],
                        help="Rebuild any of the components/dataset cache")
    args = parser.parse_args()

    ProjectDataset = Dataset.Project(os.path.join(BASE_DIR, args.project), rebuild=("target" in args.rebuild))

    project_name = os.path.basename(args.project)
    result_dir = f"result/{project_name}"
    os.makedirs(result_dir, exist_ok=True)
    
    main(ProjectDataset, output_name=f"{result_dir}/{project_name}.json", rebuild_list=args.rebuild)
