from collections import Counter, deque
import os
import signal
import tempfile
import numpy as np
import subprocess
from loguru import logger
import torch
import fcntl
import ppdeep
from tree_sitter import Language, Parser
from anytree import AnyNode

import config
from .embedding import CodeBertEmbedding

from .cfg import CFGExtractor
from .taintflow import TaintFlowExtractor
from .utils import TRACE_DIR, diff_lines, line_hash

joern_path = config.joern_path


class FileLockManager:
    def __init__(self, file_path):
        self.file_path = file_path

    def __enter__(self):
        self.file = open(self.file_path, "w")
        fcntl.flock(self.file, fcntl.LOCK_EX)
        return self.file

    def __exit__(self, exc_type, exc_value, traceback):
        fcntl.flock(self.file, fcntl.LOCK_UN)
        self.file.close()


class FunctionManager:


    def __init__(
        self,
        embedder=None,
        src_file=None,
        src_func=None,
        dst_dir=None,
        clear=True,
        gen_cfg=True,
        gen_taint=True,
    ) -> None:
        if not src_file and not src_func:
            raise Exception("Specify at least one of the `src_file` and `src_func`.")

        self.need_clear = clear

        if not src_file:
            self.src_file = "default"
        else:
            self.src_file = src_file

        self.unique_name = os.path.basename(self.src_file)

        if not src_func:
            with open(self.src_file, "r") as f:
                src_func = f.read()

        self.src_func = src_func

        logger.debug(f"processing file {self.src_file}")

        if not dst_dir:
            self.base_dir = f"{tempfile.mkdtemp()}"
        else:
            self.base_dir = f"{TRACE_DIR}/{dst_dir}/{self.unique_name}"
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)

        self.script_dir = f"{TRACE_DIR}/scripts/"

        self.code_file = f"{self.base_dir}/{self.unique_name}.c"

        self.cpg_file = f"{self.base_dir}/{self.unique_name}.cpg.bin"

        self.script_file = f"{self.script_dir}/taint2json.sc"

        self.ast_parser_file = f"{self.script_dir}/cppparser.so"

        self.taint_file = f"{self.base_dir}/{self.unique_name}.taint.json"

        self.cfg_dir = f"{self.base_dir}/cfg"

        self.cfg_file = f"{self.cfg_dir}/1-cfg.dot"

        self.npy_file = f"{self.base_dir}/{self.unique_name}.npy"

        self.npy_diff_file = f"{self.base_dir}/{self.unique_name}.diff.npy"

        if not os.path.exists(self.code_file):
            self.__generate_code_file()

   
        self.cpg_file_lock = f"{self.cpg_file}.lck"

        if (
            gen_taint
            and not os.path.exists(self.taint_file)
            and not os.path.exists(f"{self.taint_file}.err")
        ):
            self.generate_taint_file(self.script_file, self.taint_file)

        if gen_cfg and not os.path.exists(self.cfg_file):
            self.generate_cfg_file()

        self._cfg_node_dict = None

        self.line_cb_embeddings_dict = {}

        self.code_cb_embeddings_dict = {}

        self._taint_line_flows = None

        self._taint_code_flows = None

        self._tcf_codebert_embeddings = None

        self._tcf_tracer_embeddings = None

        self._tcf_sent2vec_embeddings = None

        self.token_dict = None

        self.embedder = embedder

        self._ast_parser = None

        self._ast = None

        self._ast_nodes = None
        
        self._ast_hash = None

        self._hash_dict = None

        self._fuzzy_hash = None

    def __del__(self):
        if self.need_clear and hasattr(self, "base_dir"):
            self.clear_intermediate_file()

    def __generate_code_file(self):
        logger.debug("generating code file...")

        # func = self.src_func
        # func = re.sub(r".*?(\w+\s*\([\w\W+]*\)[\s\n]*\{)", r"void \1", func, 1)  # type: ignore
        # func = re.sub(r"(\)\s*)\w+(\s*\{)", r"\1 \2", func, 1)
        # func = re.sub("(?<!:)\\/\\/.*|\\/\\*(\\s|.)*?\\*\\/", "", func)
        # func = norm(func)
        # self.normed_func = func

        with open(self.code_file, "w") as f:
            f.write(self.src_func)

    def __generate_cpg_file(self):
        logger.debug("generating cpg file...")
        cmd = f"{os.path.join(joern_path, 'joern-parse')} {self.code_file} --max-num-def 10000000 --language c --output {self.cpg_file}"
        logger.debug(cmd)

        with FileLockManager(self.cpg_file_lock):
            os.system(f"{cmd} 2>&1  > /dev/null")

    def generate_taint_file(
        self, script_file, taint_file, extra_params={}, timeout=2 * 60 * 1000
    ):
        """
        generate {self.unique_name}.taint.json
        """
        if not os.path.exists(self.cpg_file):
            self.__generate_cpg_file()

        logger.debug("generating taint file ...")
        if not os.path.exists(script_file):
            raise Exception(f"cannot find script {script_file}, generate failed.")

        params = f'bin="{self.cpg_file}",file={taint_file}'
        for k, v in extra_params:
            params += f"{k}={v}"

        cmd = f'{os.path.join(joern_path, "joern")} --script {script_file} -p {params}'
        logger.debug(cmd)

        with FileLockManager(self.cpg_file_lock):
            p = subprocess.Popen(
                cmd,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                shell=True,
                close_fds=True,
                start_new_session=True,
            )
            try:
                p.communicate(timeout=timeout)
                # p.wait()
            except subprocess.TimeoutExpired:
                p.kill()
                p.terminate()
                os.killpg(p.pid, signal.SIGTERM)

        if not os.path.exists(taint_file):
            logger.warning(
                f"generate taint file failed for {self.src_file} when using {script_file}"
            )
            f = open(f"{taint_file}.err", "w")
            f.close()
            return False

        logger.debug("generating taint file succeed")

        return True

    def generate_cfg_file(self):
        """
        generate {self.unique_name}.cfg.dot
        """
        if not os.path.exists(self.cpg_file):
            self.__generate_cpg_file()

        logger.debug("generating cfg file...")
        if os.path.exists(self.cfg_dir):
            return
            # os.removedirs(out_dir)
        cmd = f"{os.path.join(joern_path, 'joern-export')} {self.cpg_file} --repr cfg --out {self.cfg_dir}"
        logger.debug(cmd)
        with FileLockManager(self.cpg_file_lock):
            if not os.path.exists(self.cfg_file):
                os.system(cmd)

        if not os.path.exists(self.cfg_file):
            logger.warning(f"generate cfg failed for {self.src_file}\n command: {cmd}")
            return False

        logger.debug("generating cfg file succeed")
        return True

    def set_embedder(self, embedder):
        self.embedder = embedder

    @property
    def ast_parser(self):
        if not self._ast_parser:
            self._ast_parser = Parser()
            CPP_LANGUAGE = Language(self.ast_parser_file, "cpp")
            self._ast_parser.set_language(CPP_LANGUAGE)
        return self._ast_parser

    @property
    def ast(self):
        if not self._ast:
            self._ast = self.ast_parser.parse(bytes(self.src_func, "utf8"))  # type: ignore
        return self._ast

    @property
    def ast_nodes(self):
        if not self._ast_nodes:
            root_node = self.ast.root_node
            nodes = []

            def dfs(node):
                nodes.append(node.text.decode("utf-8"))
                for child in node.children:
                    dfs(child)

            def bfs(node):
                if not node:
                    return

                queue = deque()
                queue.append(node)

                while queue:
                    node = queue.popleft()
                    nodes.append(node.text.decode("utf-8"))

                    for child in node.children:
                        queue.append(child)

            dfs(root_node)
            self._ast_nodes = nodes  
                    
        return self._ast_nodes
    
    @property
    def ast_edges(self):
        edges = []

        def extract_edge(node):
            if not node:
                return

            for child in node.children:
                edges.append(
                    (node.text.decode("utf-8"), child.text.decode("utf-8"))
                )
                extract_edge(child)
        
        root_node = self.ast.root_node
        extract_edge(root_node)
        
        return edges

    @property
    def taint_line_flows(self):
        if not self._taint_line_flows:
            if not os.path.exists(self.taint_file):
                has_taint = self.generate_taint_file(self.script_file, self.taint_file)
                if not has_taint:
                    return []
            taint_line_flows = TaintFlowExtractor(self.taint_file).taint_line_flows
     
            if self.cfg_node_dict and taint_line_flows:
                allowed_lines = list(self.cfg_node_dict.keys())
                taint_line_flows = [
                    [
                        val
                        if val in allowed_lines
                        else max(filter(lambda x: x < val, allowed_lines), default=val)
                        for val in taint_line_flow
                    ]
                    for taint_line_flow in taint_line_flows
                ]

            self._taint_line_flows = taint_line_flows
        return self._taint_line_flows

    @property
    def cfg_node_dict(self):
        if not self._cfg_node_dict:
            if not os.path.exists(self.cfg_file):
                has_cfg = self.generate_cfg_file()
                if not has_cfg:
                    return {}
            self._cfg_node_dict = CFGExtractor(self.cfg_file).node_dict
        return self._cfg_node_dict

    @property
    def taint_code_flows(self):  # -> list[tuple[Any | None, ...]] | None:
        if not self._taint_code_flows:
            if self.taint_line_flows and self.cfg_node_dict:
                logger.debug("generating taint code flows...")

                self._taint_code_flows = list(
                    map(
                        lambda x: tuple(map(lambda line: self.cfg_node_dict[line], x)),  # type: ignore
                        self.taint_line_flows,
                    )
                )
        return self._taint_code_flows

    def embeddings_mean(self, code_embeddings):

        # code_embeddings = list(
        #     filter(
        #         lambda code_embedding: code_embedding.numel() != 0
        #         and code_embedding.shape != torch.Size([]),
        #         code_embeddings,
        #     )
        # )
        if len(code_embeddings) == 0:
            return np.array([])
        # print(code_embeddings)
        code_embeddings = torch.stack(code_embeddings)
        embeddings = torch.mean(code_embeddings.squeeze(), dim=0)
        embeddings_numpy = embeddings.detach().numpy()
        return embeddings_numpy

    def embedding_line_flows(self, line_flows):
        """
        [[1,2,3], [2,3,5], ...]
        """
        embs = [self.embedding_line_flow(tlf) for tlf in line_flows]
        # for tlf in line_flows:
        #     print(tlf)
        #     for line in tlf:
        #         e = self.line_cb_embeddings_dict.get(line)
        #         if e is None:
        #             code = self.cfg_node_dict[line]
        #             e = self.embedder.embedding(code)
        #     self.embedding_line_flow(tlf)
        return np.array(embs)

    def embedding_line_flow(self, line_flow):

        if not self.embedder:
            self.set_embedder(CodeBertEmbedding())
        tlf_embeddings = []
        for line in line_flow:
            emb = self.line_cb_embeddings_dict.get(line)
            if emb is None:
                code = self.cfg_node_dict[line]
                emb = self.embedder.embedding(code)
                if emb.numel() == 0 or emb.shape == torch.Size([]):
                    logger.error(f"strange embedding : {code}: {emb}")
                    continue
                self.line_cb_embeddings_dict[line] = emb
                # self.code_cb_embeddings_dict[] = emb
            tlf_embeddings.append(emb)
       
        return self.embeddings_mean(tlf_embeddings)

    def embedding_code_flows(self, code_flows):
        return np.array([self.embedding_code_flow(cf) for cf in code_flows])

    def embedding_code_flow(self, code_flow):
   
        if not self.embedder:
            self.set_embedder(CodeBertEmbedding())
        tcf_embeddings = []
        for code in code_flow:
            emb = self.code_cb_embeddings_dict.get(code)
            if emb is None:
                emb = self.embedder.embedding(code)
                if emb.numel() == 0 or emb.shape == torch.Size([]):
                    logger.error(f"strange embedding : {code}: {emb}")
                    continue
                self.code_cb_embeddings_dict[code] = emb
            tcf_embeddings.append(emb)
        return self.embeddings_mean(tcf_embeddings)

    @property
    def tcf_codebert_embeddings(self):
        if self._tcf_codebert_embeddings is None:
            # if os.path.exists(self.npy_file):
            # self._tcf_codebert_embeddings = np.load(self.npy_file)
            if self.taint_line_flows:
                self._tcf_codebert_embeddings = self.embedding_line_flows(
                    self.taint_line_flows
                )

                # np.save(self.npy_file, self._tcf_codebert_embeddings)
        return self._tcf_codebert_embeddings

    @property
    def embeddings(self):
        logger.debug("getting property embeddings")
        return self.tcf_codebert_embeddings

    def clear_intermediate_file(self):
        if os.path.exists(self.base_dir):
            import shutil

            shutil.rmtree(self.base_dir)

    @property
    def hash_dict(self):
        if self._hash_dict is None:
            self._hash_dict = Counter()
            for line in self.src_func.splitlines():
                hash = line_hash(line)
                self._hash_dict[hash] += 1

        return self._hash_dict

    @property
    def fuzzy_hash(self):
        if self._fuzzy_hash is None:
            self._fuzzy_hash = ppdeep.hash(self.src_func)
        return self._fuzzy_hash

    # @property
    # def fuzzy_hash(self):
    #     if self._fuzzy_hash is None:
    #         self._fuzzy_hash = ppdeep.hash(self.ast_nodes)
    #     return self._fuzzy_hash
    
    def get_ast_hash(self):
        root_node = self.ast.root_node

        child_dict = {}
        
        
        def init_child_dict(node):
            children = []
            for child in node.children:
                children.append(child.id)
            child_dict[node.id] = children
            for child in node.children:
                init_child_dict(child)
        
    
        new_tree = AnyNode(id=0, text=None, data=None)
        nodes = [] 
        def create_tree(root, node, parent=None):
            id = len(nodes)
            text = node.text.decode('utf-8')
            text_hash = hash(text)
            nodes.append(text)
            if id == 0:
                root.text = text
                root.data = node
                root.hash = text_hash
            else:
                newnode = AnyNode(id=id, text=text, hash=text_hash, data=node, parent=parent)
            for child in node.children:
                create_tree(root, child, parent=root if id == 0 else newnode)
                
        
        id2hash = {}
        id2number = {}
        def get_hash():
            for i in range(len(child_dict) - 1, -1, -1):
                token = nodes[i]
                if not child_dict[i]:
                    id2hash[i] = hash(token)
                    id2number[i] = 1
                else:
                    h = hash(token)
                    n = 1
                    if token == 'binary_expression':
                        childtoken = []
                        for c in child_dict[i]:
                            childtoken.append(nodes[c])
                        if '/' in childtoken or '-' in childtoken:
                            j = 1
                            for child_id in child_dict[i]:
                                h += j * id2hash[child_id]  
                                n += id2number[child_id]              
                                j += 1
                        else:
                            for child_id in child_dict[i]:
                                h += id2hash[child_id]     
                                n += id2number[child_id]                   
                    else:
                        for child_id in child_dict[i]:
                            h += id2hash[child_id]   
                            n += id2number[child_id]                 
                    id2hash[i] = h
                    id2number[i] = n

        
        create_tree(new_tree, root_node)
        
        init_child_dict(new_tree)
        get_hash()
        
        hash_list_array =  [[] for i in range(len(nodes) + 1)]
        for i in range(len(id2number)):
            children_num = id2number[i]
            hash_list_array[children_num].append(i) 

        return hash_list_array, id2hash, child_dict

        
    @property
    def ast_hash(self):
        if not self._ast_hash:
            self._ast_hash = self.get_ast_hash()
        return self._ast_hash


class FunctionManagerV2(FunctionManager):


    def __init__(
        self,
        embedder: CodeBertEmbedding,
        src_file=None,
        src_func=None,
        dst_dir=None,
        clear=True,
    ):
        super().__init__(
            embedder,
            src_file=src_file,
            src_func=src_func,
            dst_dir=dst_dir,
            clear=clear,
            gen_cfg=False,
        )

    @property
    def cfg_node_dict(self):
        blacklist = ["else", "do"]
        if not self._cfg_node_dict:
            self._cfg_node_dict = {}
            for line, code in enumerate(self.src_func.splitlines()):
                if len(code) <= 1 or code in blacklist:
                    continue
                self._cfg_node_dict[line] = code

        return self._cfg_node_dict


class FunctionPairManager:
    def __init__(
        self,
        vuln_function_manager: FunctionManager,
        patch_function_manager: FunctionManager,
    ):
        self.vuln_fm = vuln_function_manager
        self.patch_fm = patch_function_manager

    def get_diff_lines(self):
        return diff_lines(
            self.vuln_fm.src_func.splitlines(), self.patch_fm.src_func.splitlines()
        )

    def get_diff_lines_hash(self, filter_lines=[]):
        vuln_diff_line, patch_diff_line = self.get_diff_lines()
        
        if filter_lines != []:
            vuln_diff_line = [line for line in vuln_diff_line if line not in filter_lines]
            patch_diff_line = [line for line in patch_diff_line if line not in filter_lines]
            
        return (
            list(map(line_hash, vuln_diff_line)),
            list(map(line_hash, patch_diff_line)),
        )

    def get_diff_tcfs(self):
        """
        get taint flow
        get diff taint flow
        """
        if not self.vuln_fm.taint_code_flows or not self.patch_fm.taint_code_flows:
            return list(), list()

        vuln_tcfs = set(self.vuln_fm.taint_code_flows)
        patch_tcfs = set(self.patch_fm.taint_code_flows)
        vuln_unique_tcfs = vuln_tcfs.difference(patch_tcfs)
        patch_unique_tcfs = patch_tcfs.difference(vuln_tcfs)
        return list(vuln_unique_tcfs), list(patch_unique_tcfs)

    def get_diff_embeddings(self, embed_type="codebert"):
        """ """
        self.vuln_fm.npy_diff_file = (
            f"{self.vuln_fm.base_dir}/{embed_type}/{self.patch_fm.unique_name}.diff.npy"
        )
        if not os.path.exists(f"{self.vuln_fm.base_dir}/{embed_type}"):
            os.makedirs(f"{self.vuln_fm.base_dir}/{embed_type}", exist_ok=True)

        self.patch_fm.npy_diff_file = (
            f"{self.patch_fm.base_dir}/{embed_type}/{self.vuln_fm.unique_name}.diff.npy"
        )
        if not os.path.exists(f"{self.patch_fm.base_dir}/{embed_type}"):
            os.makedirs(f"{self.patch_fm.base_dir}/{embed_type}", exist_ok=True)

        vuln_tcfs, patch_tcfs = [], []
        if not os.path.exists(self.vuln_fm.npy_diff_file) or not os.path.exists(
            self.patch_fm.npy_diff_file
        ):
            vuln_tcfs, patch_tcfs = self.get_diff_tcfs()

            logger.debug(
                f"getting different taint flow embeddings in {len(vuln_tcfs)} v.s {len(patch_tcfs)}"
            )

        # get it from npy
        if os.path.exists(self.vuln_fm.npy_diff_file):
            vuln_emb = np.load(self.vuln_fm.npy_diff_file)
        else:
            vuln_emb = self.vuln_fm.embedding_code_flows(vuln_tcfs)
            np.save(self.vuln_fm.npy_diff_file, vuln_emb)

        # get it from npy
        if os.path.exists(self.patch_fm.npy_diff_file):
            patch_emb = np.load(self.patch_fm.npy_diff_file)
        else:
            patch_emb = self.patch_fm.embedding_code_flows(patch_tcfs)
            np.save(self.patch_fm.npy_diff_file, patch_emb)

        return vuln_emb, patch_emb
