import os.path
import yaml


def load_config():
    config_file = "config.yml"
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "basic": {
                "dataset": {"old_new_func_dataset_path": "", "normal_sample_dataset_path": ""},
                "trace": {"codebert_model_path": "", "joern_path": ""},
                "workers": {"bloom_filter": 5, "token": 15, "syntax": 6, "trace": 32}
            },
            "experiment": {
                "token_filter": {"jaccard_sim_threshold": 0.7},
                "trace": {
                    "ast_sim_threshold_min": 0.7,
                    "ast_sim_threshold_max": 0.9,
                    "redis_host": "127.0.0.1",
                    "redis_port": "6379",
                },
            },
        }

        with open(config_file, "w") as f:
            yaml.dump(config, f)

        print("config.yml not exist, quiting")
        exit(1)

    return config


config = load_config()

"""
check basic config
"""
basic_dataset = config["basic"].get("dataset", {})
old_new_func_dataset_path = basic_dataset.get("old_new_func_dataset_path")
assert old_new_func_dataset_path is not None

normal_sample_dataset_path = basic_dataset.get("normal_sample_dataset_path")
assert normal_sample_dataset_path is not None


trace = config["basic"].get("trace", {})
codebert_model_path = trace.get("codebert_model_path")
assert codebert_model_path is not None

joern_path = trace.get("joern_path")
assert joern_path is not None

workers = config["basic"].get("workers", {})
bloom_filter_worker = workers.get("bloom_filter")
assert bloom_filter_worker is not None
token_worker = workers.get("token")
assert token_worker is not None
syntax_worker = workers.get("syntax")
assert syntax_worker is not None
trace_worker = workers.get("trace")
assert trace_worker is not None

"""
check experiment config
"""
experiment_token_filter = config["experiment"].get("token_filter", {})
jaccard_sim_threshold = experiment_token_filter.get("jaccard_sim_threshold", 0.7)

experiment_trace = config["experiment"].get("trace", {})
ast_sim_threshold_min = experiment_trace.get("ast_sim_threshold_min", 0.7)
ast_sim_threshold_max = experiment_trace.get("ast_sim_threshold_max", 0.9)

redis_host = experiment_trace.get("redis_host")
redis_port = experiment_trace.get("redis_port")
