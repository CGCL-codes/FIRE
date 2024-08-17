# FIRE-Public

FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring
Vulnerability Detection.

## Overview

The project consists four components(packages): `BloomFilter`(SFBF, Section 3.1), `TokenFilter`(Token Similarity Filter, Section 3.2),
`SyntaxFilter`(AST Similarity Filter, Section 3.3), Trace(Vulnerability Identification Phase, Section 4).

Besides, we provide utils classes in `Dataset` package to load dataset, including the `Old-New-Funcs` dataset, `NormalSample`dataset, and a class to load the target system (`Dataset/target_project.py`).

During the detection, `cache`, `log`, `processed`, `result`, `workspace` five directories are used.

We provide dockerfile and a flask server(`server.py`), so you can build the project to docker and use HTTP Request to detect vulnerability.

## Installation

### Install Python Requirements

#### conda

```shell
conda env new -f environment.yml
```

#### pip
```shell
# Install Python Requirements Except Torch
pip install -r requirements.txt
# Install Torch
pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
```

### Install Codebert

Put `codebert-base` in `resource/codebert`.

You can find `codebert` here [microsoft/codebert-base](https://huggingface.co/microsoft/codebert-base).

### Install Joern

Joern needs Java to run. In our project we use `jdk-17.0.11`.

#### Install Java

Get tar.gz tarball of jdk and unzip it to `resource/jdk-17.0.11`.

```bash
JAVA_HOME="/path/to/FIRE-public/resource/jdk-17.0.11"
PATH=$PATH:$JAVA_HOME/bin
java --version
```
```
java 17.0.11 2024-04-16 LTS
Java(TM) SE Runtime Environment (build 17.0.11+7-LTS-207)
Java HotSpot(TM) 64-Bit Server VM (build 17.0.11+7-LTS-207, mixed mode, sharing)
```

#### Install Joern-cli

We use version `1.2.1` of Joern. You can find Joern in [joernio/joern](https://github.com/joernio/joern).

Please download the zip tarball of Joern and unzip it to `resource/joern-cli`

```bash
./resource/joern-cli/joern
```
```
     ██╗ ██████╗ ███████╗██████╗ ███╗   ██╗
     ██║██╔═══██╗██╔════╝██╔══██╗████╗  ██║
     ██║██║   ██║█████╗  ██████╔╝██╔██╗ ██║
██   ██║██║   ██║██╔══╝  ██╔══██╗██║╚██╗██║
╚█████╔╝╚██████╔╝███████╗██║  ██║██║ ╚████║
 ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
Version: 1.2.1
Type `help` or `browse(help)` to begin
      
joern>  
```

#### About Ctags

Since Ctags is a lightweight open-source software, we put its binary version in `Database/universal-ctags` with COPYING.
So you don't need to install it. However, you should make sure +x is set to ctags file before run.

```bash
./Dataset/universal-ctags/ctags --version
```
```
Universal Ctags 6.0.0(293f11e), Copyright (C) 2015-2022 Universal Ctags Team
Universal Ctags is derived from Exuberant Ctags.
Exuberant Ctags 5.8, Copyright (C) 1996-2009 Darren Hiebert
  Compiled: Dec 20 2023, 10:38:07
  URL: https://ctags.io/
  Output version: 0.0
  Optional compiled features: +wildcards, +regex, +gnulib_regex, +iconv, +option-directory, +xpath, +json, +interactive, +yaml, +packcc, +optscript
```

#### About Redis

`Trace` need Redis for caching. We use Redis docker in our experiments. If you want to build docker,
please make sure you have put redis 7.2.3 in `resource/redis-7.2.3`, and the external redis docker is **no need** in the run 
since we will install one in the procedure of the building.

```bash
docker run -p 6379:6379 redis:7.2.3
```

## Datasets

We use Old-New-Funcs dataset to store all the vulnerabilities and patches pairs which is used in all the components of FIRE.

### Old-New-Funcs Dataset

We suggest to put the dataset to `resource/OldNewFuncs`.

Unfortunately we can not open source the dataset we used in this project, but you can build one using your own data following the structure below.

An Example of the Old-New-Funcs dataset folder structure:

```
|-- OldNewFuncs
|   |-- ffmpeg (software directory)
|   |   |-- CVE-2009-0385 (CVE directory)
|   |   |   |-- CVE-2009-0385_CWE-189_72e715fb798f2cb79fd24a6d2eaeafb7c6eeda17_4xm.c_1.1_fourxm_read_header_OLD.vul [Vulnerable Version]
|   |   |   |-- CVE-2009-0385_CWE-189_72e715fb798f2cb79fd24a6d2eaeafb7c6eeda17_4xm.c_1.1_fourxm_read_header_NEW.vul [Patch Version]
|   |   |   |-- ...Other Old-New-Funcs files (with the filename extension `.vul`)
|   |   |-- ...Other CVEs
|   |-- ...Other Software
```

We do not utilize the software and CVE directory name. However, we utilize the old-new-funcs file's filename 
in our project. Each Old-New-Funcs file should store a function.

The Old-New-Funcs filename structure:
```
[CVE-No.]_[CWE-No.]_[Commit]_[File Extracted From]_[Version]_[Function Name]_[OLD/NEW].vul
```
`OLD` tag refers to vulnerability version, while `NEW` tag refers to patch version. 

We utilized the `CVE`, `Function Name` and `OLD/NEW` part of the filename in FIRE. So please set them properly.

### ~~~NormalSample Dataset~~~ (No need anymore)

The NormalSample Dataset Structure:

We suggest to put the dataset at `resource/NormalSample`

```
|-- NormalSample Dataset
|   |-- ffmpeg (software directory)
|   |   |-- ...functions
|   |-- ...Other Software
```

There is no extra constraints for the filenames of the normal functions store in the software directory.

## How To Run

### Run Locally

Make sure you have properly installed all the requirements and prepared the datasets before run.

You can execute `python3 main --help` to read the help message of this project.

Currently, FIRE only runs on Linux.

#### Basic Usage
```bash
python3 main.py /path/to/target/system
```

#### Help Message
```bash
python3 main.py --help
```
```
usage: main.py [-h] [--rebuild [{bloomFilter,old-new-funcs,normal-sample,target} ...]] project

Extract data from project dir

positional arguments:
  project               Path to the project dir

options:
  -h, --help            show this help message and exit
  --rebuild [{bloomFilter,old-new-funcs,target} ...]
                        Rebuild any of the components/dataset cache
```

#### Rebuild Option

We provide rebuild option to rebuild the cache when there are any updates to the dataset. We suggest to apply all the rebuild options first time before running the project.

If you update Old-New-Funcs Dataset, please rebuild `bloomFilter` and `old-new-funcs`.

If you do not specify any rebuild options, `target` option is set default to extract function of the target system each time before the vulnerbility detection.

Use space to separate the option if you want to apply multiple rebuild option.

#### Results

Detection results not only display in the console, but also in the `result` folder as well. You can find the detection result in `result/[target-system]`.

### Run Remote or In Docker

Run `server.py` if you want to run FIRE remote. If you use docker, `server.py` runs automatically.
This will open a flask server on port 8000 on the machine/docker. You can change the port in the `server.py`.

```bash
python3 server.py
```

You can publish a vulnerability detecting job using the following HTTP requests.

#### Request

- Method: GET
- URL: /process?git-url={git-url}&branch={branch}
  - `git-url`: git url to the target system.
  - `branch`: tag or branch of the target system.

#### Response

- Body(Json)
  - `time`: Project Runtime.
  - `vul`: Vulnerabilities Detected.
  - `vul_cnt`: Count of the detected vulnerabilities.

#### Docker build

You should fully generate the cache (old-new-funcs and bloomFilter) before building the docker.

```bash
docker build .
```

### Notes

We use lazy caching technique (generate the cache vector when the vulnerability and patch function are needed) instead of generate vectors of all vulnerability and patch functions in advance in `Trace` component to accelerate the experiments, making the first run of FIRE might slower than expected. However, in production environment, all the vectors of vulnerability and patch function should generate in advance. So please **run again** to get the actual run speed. 

The experiments are conducted on a machine with a 3.40 GHz Intel i7-13700k processor and 48 GB of RAM, running on ArchLinux with Linux Zen Kernel (Appendix C). **Please adjust the max process in each component to avoid crashes according to your experiments environments**.

# Publication
Siyue Feng, Yueming Wu, Wenjie Xue, Sikui Pan, Deqing Zou, Yang Liu and Hai Jin. 2024. FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring Vulnerability Detection. In Proceedings of the 33rd USENIX Security Symposium (USENIX Security ’24), August 14–16, 2024, Philadelphia Marriott Downtown in Philadelphia, PA, USA, 18 pages. 


If you use our dataset or source code, please kindly cite our paper:
```
@INPROCEEDINGS{fire2024,
  author={Feng, Siyue and Wu, Yueming and Xue, Wenjie and Pan, Sikui and Zou, Deqing and Liu, Yang and Jin, Hai},
  booktitle={33rd USENIX Security Symposium (USENIX Security ’24)}, 
  title={FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring Vulnerability Detection}, 
  year={2024}}
```

# Support or Contact
FIRE is developed in the National Engineering Research Center for Big Data Technology and System, Services Computing Technology and System Lab, Hubei Key Laboratory of Distributed System Security, Hubei Engineering Research Center on Big Data Security, Cluster and Grid Computing Lab, Huazhong University of Science and Technology, Wuhan, China by Siyue Feng (fengsiyue@hust.edu.cn), Yueming Wu (wuyueming21@gmail.com), Wenjie Xue (xuewenjie2021@hust.edu.cn), Sikui Pan (skpan@hust.edu.cn), Deqing Zou (deqingzou@hust.edu.cn), Yang Liu (yangliu@ntu.edu.sg), and Hai Jin (hjin@hust.edu.cn).
