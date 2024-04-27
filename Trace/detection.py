from collections import Counter
import json
import os
import traceback
from typing import List
from line_profiler import profile
import numpy as np
import ppdeep

from loguru import logger

import config
from .serializer import Serializer
from .embedding import CodeBertEmbedding

from Trace.manager import (
    FunctionManager,
    FunctionPairManager,
)
from Trace.utils import (
    # diff_embedding_dict
    # error_func_list,
    # patch_line_hash_dict,
    vuln_to_patch_dict,
    norm_line,
    diff_lines,
)


def max_mean_col(matrix):
    max_each_col = np.nanmax(matrix, axis=0)
    mean_max = np.nanmean(max_each_col)
    return mean_max.tolist()


def cos_similarity_matrix(m1, m2):
    return np.dot(m1, m2.T) / (
        np.linalg.norm(m1, axis=1).reshape(-1, 1) * np.linalg.norm(m2, axis=1)
    )


def cos_similarity(m1, m2):
    sim_matrix = cos_similarity_matrix(m1, m2)
    sim = max_mean_col(sim_matrix)
    return sim


def fuzzy_hash_similarity(s1, s2):
    return ppdeep.compare(ppdeep.hash(s1), ppdeep.hash(s2))


def get_fuzzy_hash(code, vuln_file, patch_file):
    with open(vuln_file, "r") as v, open(patch_file, "r") as p:  # type: ignore
        vuln_sim = fuzzy_hash_similarity(code, v.read())
        patch_sim = fuzzy_hash_similarity(code, p.read())

        return vuln_sim, patch_sim


# @profile
def detect_vulnerable_with_initialize(
    code: str,
    dst_file: str,
    similar_list: List[str],
    trace_all_result_queue=None,
) -> tuple[bool, list[str]]:
    try:
        cur_dir = "v1"
        dst_dir = f"{cur_dir}/oldnew"
        embedder = None # type: ignore
        s = Serializer()

        
        logger.debug(f"starting test file : {dst_file}")
        code_manager = FunctionManager(
            src_file=dst_file,
            src_func=code,
            # embedder=embedder,
            # dst_dir=f"{cur_dir}/target",
            # clear=False,
            clear=True,
            gen_cfg=False,
            gen_taint=False,
        )
        # print(code_manager.ast_seq)

        logger.debug("init file completed")

        output_list = []
        cve_list = []


        for vuln_file in similar_list:
            patch_file = vuln_to_patch_dict.get(vuln_file)
            if patch_file is None:
                logger.debug(f"no patch file for {vuln_file}")
                continue

            vuln_name = os.path.basename(vuln_file)
            cve_id = vuln_name.split("_")[0]
            

            if (
                not s.is_error_func(vuln_name)
                and s.get_diff_embedding(vuln_name) is None
            ):
            
                embedder = CodeBertEmbedding()
                logger.debug(f"init {vuln_file}.")

                vuln_manager = FunctionManager(
                    src_file=vuln_file,
                    embedder=embedder,
                    dst_dir=dst_dir,
                    clear=False,
                    gen_cfg=False,
                    gen_taint=False,
                )
                patch_manager = FunctionManager(
                    src_file=patch_file,
                    embedder=embedder,
                    dst_dir=dst_dir,
                    clear=False,
                    gen_cfg=False,
                    gen_taint=False,
                )

                func_pair_manager = FunctionPairManager(vuln_manager, patch_manager)
                
                # diff embedding
                logger.debug(f"init {vuln_file} diff embedding.")

                (
                    vuln_diff_embedding,
                    patch_diff_embedding,
                ) = func_pair_manager.get_diff_embeddings()

                if vuln_diff_embedding.size == 0 or patch_diff_embedding.size == 0:
                    logger.debug(
                        f"Embedding diff wrong: {vuln_file}:{vuln_diff_embedding.shape}/{patch_diff_embedding.shape}"
                    )

                    s.set_error_func(vuln_name)
                else:
                    s.set_diff_embedding(
                        vuln_name,
                        (
                            vuln_diff_embedding,
                            patch_diff_embedding,
                        ),
                    )

                logger.debug(f"init {vuln_file} diff embedding ok.")

            info = {
                "target_file": dst_file,
                "vuln_file": vuln_file,
                "patch_file": patch_file,
            }
      
            logger.debug(f"testing {vuln_file}")

            vuln_cond = []
        
            def finish():
                if trace_all_result_queue:
                    trace_all_result_queue.put(
                        {**info, **{"datail": vuln_cond, "predict": all(vuln_cond)}}
                    )

                if all(vuln_cond):
                    output_list.append(vuln_file)
                    cve_list.append(cve_id)
                    
            if s.is_error_func(vuln_name):
                vuln_cond.append("no vuln_file emb")
                finish()
                continue

           
            if not code_manager.taint_line_flows:
                logger.debug("Empty taint line flows.")
                vuln_cond.append("no target_file emb")
                finish()
                continue

            if not embedder:
                embedder = CodeBertEmbedding()
                code_manager.set_embedder(embedder)
                
            code_embedding = code_manager.embeddings

            vuln_diff_embedding, patch_diff_embedding = s.get_diff_embedding(vuln_name)  # type: ignore

           
            vuln_sim = cos_similarity(code_embedding, vuln_diff_embedding)
            patch_sim = cos_similarity(code_embedding, patch_diff_embedding)

           
        
            vuln_cond_sim = True
            if vuln_sim < patch_sim:
                vuln_cond_sim = False

            vuln_cond.append(vuln_cond_sim)
            vuln_cond.extend([vuln_sim, patch_sim])
            
            if trace_all_result_queue:
                trace_all_result_queue.put(
                    {**info, **{"datail": vuln_cond, "predict": all(vuln_cond)}}
                )
                    
            if all(vuln_cond):
                output_list.append(vuln_file)
                cve_list.append(cve_id)

        return output_list != [], output_list

    except Exception as e:
        traceback.print_exc()
        raise Exception(f"error when process file {dst_file} : {str(e)}")
