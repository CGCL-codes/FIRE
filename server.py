import json
import os
import shutil
import subprocess
import time

import yaml
from flask import Flask, request

app = Flask(__name__)
process_running = False


@app.route('/')
def hello():
    return 'Hello, World!'


def change_yml(jaccard_sim_threshold=0.7, ast_hash_sim_threshold_min=0.7):
    if os.path.exists("config.yml"):
        with open("config.yml", "r") as f:
            config = yaml.safe_load(f)
        config["experiment"]["token_filter"]["jaccard_sim_threshold"] = jaccard_sim_threshold
        config["experiment"]["trace"]["ast_sim_threshold_min"] = ast_hash_sim_threshold_min
        with open("config.yml", "w") as f:
            yaml.dump(config, f)


@app.route('/process')
def process():
    global process_running

    if not process_running:
        process_running = True
        try:
            shutil.copy("config.default.yml", "config.yml")
            git_url = request.args.get('git_url', '')
            branch = request.args.get('branch', '')
            jaccard_sim_threshold_str = request.args.get('jaccard_sim_threshold', '0.7')
            ast_sim_threshold_min_str = request.args.get('ast_sim_threshold_min', '0.7')
            ast_sim_threshold_min = float(ast_sim_threshold_min_str)
            jaccard_sim_threshold = float(jaccard_sim_threshold_str)
            change_yml(jaccard_sim_threshold, ast_sim_threshold_min)

            if git_url and branch:
                git_name = os.path.basename(git_url.rstrip('/'))
                subprocess.call('git clone --branch %s --depth=1 %s' % (branch, git_url), shell=True)
                start_time = time.time()
                code = subprocess.call('python3 main.py %s' % git_name, shell=True)
                end_time = time.time()
                shutil.rmtree(git_name)
                if code != 0:
                    process_running = False
                    return json.dumps({'Error': 'Detect Failed'}), 500

                result_dir = f'result/{git_name}'
                trace_file = os.path.join(result_dir, f'{git_name}.trace.csv')
                log_file = os.path.join(result_dir, f'{git_name}.json')
                info_file = os.path.join(result_dir, f'{git_name}.detect_info.json')
                if os.path.exists(log_file):

                    with open(log_file, 'r') as f:
                        orig_vul_json = json.load(f)

                    vul_cnt = orig_vul_json["all"]
                    vul_json = {}
                    for vul in orig_vul_json["vul"]:
                        if vul["dst"] not in vul_json:
                            vul_json[vul["dst"]] = vul["sim"]
                        else:
                            vul_json[vul["dst"]].extend(vul["sim"])

                    if os.path.exists(trace_file):
                        with open(trace_file, "r") as f:
                            csv_info = f.read()
                    else:
                        csv_info = ""

                    if os.path.exists(info_file):
                        with open(info_file, "r") as f:
                            detect_info = json.load(f)
                    else:
                        detect_info = {}

                    response = json.dumps(
                        {"time": end_time - start_time, "vul": vul_json, "vul_cnt": vul_cnt, "csv_info": csv_info,
                         "detect_info": detect_info})
                else:
                    return json.dumps({'Error': 'Log file not found.'}), 500

                shutil.rmtree(result_dir, ignore_errors=True)
                process_running = False
                return response
            else:
                process_running = False
                return json.dumps({'Error': 'Missing git_url or branch parameter.'}), 400

        except Exception as e:
            process_running = False
            return json.dumps({'Error': str(e)}), 500

    else:
        return json.dumps({'Error': 'Another process is already running.'}), 429


if __name__ == '__main__':
    app.run("0.0.0.0", port=8000)
