from collections import Counter
import os
import traceback
from typing import List
import ppdeep

from loguru import logger

import config
from Trace.serializer import Serializer

from Trace.manager import (
    FunctionManager,
    FunctionPairManager,
)
from Trace.utils import (
    # diff_embedding_dict
    # error_func_list,
    # patch_line_hash_dict,
    vuln_to_patch_dict,
)


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
    vulnerable_func_queue,
    trace_all_result_queue=None,
    ast_sim_threshold_min=config.ast_sim_threshold_min,
    ast_sim_threshold_max=config.ast_sim_threshold_max,
) -> tuple[bool, list[str]]:
    try:
        cur_dir = "v1"
        dst_dir = f"{cur_dir}/oldnew"
        s = Serializer()

        # 1
        logger.debug(f"starting test file : {dst_file}")
        code_manager = FunctionManager(
            src_file=dst_file,
            src_func=code,
            # dst_dir=f"{cur_dir}/target",
            # clear=False,
            clear=True,
            gen_cfg=False,
            gen_taint=False,
        )

        logger.debug("init file completed")

        output_list = []
        cve_list = []

        ast_sim_dict = {}
        # line_hash_dict_dict = {}
        near_sims_list = []
        
        for vuln_file in similar_list:
            patch_file = vuln_to_patch_dict.get(vuln_file)
            if patch_file is None:
                logger.debug(f"no patch file for {vuln_file}")
                continue

            vuln_name = os.path.basename(vuln_file)
            cve_id = vuln_name.split("_")[0]


            logger.debug(f"init {vuln_file}.")

            vuln_manager = FunctionManager(
                src_file=vuln_file,
                dst_dir=dst_dir,
                clear=False,
                gen_cfg=False,
                gen_taint=False,
            )
            patch_manager = FunctionManager(
                src_file=patch_file,
                dst_dir=dst_dir,
                clear=False,
                gen_cfg=False,
                gen_taint=False,
            )

            func_pair_manager = FunctionPairManager(vuln_manager, patch_manager)

            if not s.get_patch_line(vuln_name) or not s.get_line_hash_dict(vuln_name):
                # diff line
                logger.debug(f"init {vuln_file} patch line.")

                diff_line = func_pair_manager.get_diff_lines_hash(filter_lines=['{', '}'])

                s.set_patch_line(vuln_name, diff_line)
                s.set_line_hash_dict(
                    vuln_name,
                    (
                        vuln_manager.hash_dict,
                        patch_manager.hash_dict,
                    ),
                )

                logger.debug(f"init {vuln_file} patch line ok.")

            # if not s.get_fuzzy_hash(vuln_name):
            #     s.set_fuzzy_hash(
            #         vuln_name, (vuln_manager.fuzzy_hash, patch_manager.fuzzy_hash)
            #     )

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
                    
                    
            dst_hash_dict = code_manager.hash_dict
            vuln_hash_dict, patch_hash_dict = s.get_line_hash_dict(vuln_name)
            vuln_hash_dict, patch_hash_dict = (
                Counter(vuln_hash_dict),
                Counter(patch_hash_dict),
            )
            

            
            del_lines, add_lines = s.get_patch_line(vuln_name)

            vuln_cond_del_lines = True
            for del_line in del_lines:
                if (
                    vuln_hash_dict[del_line] != patch_hash_dict[del_line]
                    and dst_hash_dict[del_line] != vuln_hash_dict[del_line]
                ):
                    vuln_cond_del_lines = False
                    break

            vuln_cond.append(vuln_cond_del_lines)
            if del_lines == []:
                vuln_cond.append("no del line")
            if not vuln_cond_del_lines:
                finish()
                continue


            
            vuln_cond_add_lines = True
            for add_line in add_lines:
                if (
                    vuln_hash_dict[add_line] != patch_hash_dict[add_line]
                    and dst_hash_dict[add_line] != vuln_hash_dict[add_line]
                ):
                    vuln_cond_add_lines = False
                    break

            vuln_cond.append(vuln_cond_add_lines)
            if add_lines == []:
                vuln_cond.append("no add line")
            if not vuln_cond_add_lines:
                finish()
                continue


            
            def jaccard_similarity(list1, list2):
                count1 = {}
                count2 = {}
                
                for item in list1:
                    count1[item] = count1.get(item, 0) + 1
                
                for item in list2:
                    count2[item] = count2.get(item, 0) + 1
                
                intersection = sum(min(count1.get(item, 0), count2.get(item, 0)) for item in set(list1 + list2))
                union = sum(max(count1.get(item, 0), count2.get(item, 0)) for item in set(list1 + list2))
                
                similarity = intersection / union
                
                return similarity
                
            vuln_sim, patch_sim = (
                # calculate sim
                jaccard_similarity(code_manager.ast_nodes, vuln_manager.ast_nodes),
                jaccard_similarity(code_manager.ast_nodes, patch_manager.ast_nodes),
            )


            
            if vuln_sim < ast_sim_threshold_min:
                vuln_cond.append(False)
            elif vuln_sim < patch_sim:
                if patch_sim - vuln_sim > 0.15:
                    vuln_cond.append(True)
                    near_sims_list.append(vuln_file)
                else:
                    vuln_cond.append(False)
            else:
                vuln_cond.append(True)
                
            ast_sim_dict[vuln_file] = vuln_sim
                
            vuln_cond.extend([vuln_sim or "0", patch_sim or "0"])                
            finish()
                

        if len(output_list) > 1:
            if len(output_list) != len(set(cve_list)):

                cve_dict = {}
                for vuln_file in output_list:
                    cve_id = os.path.basename(vuln_file).split("_")[0]
                    if cve_id in cve_dict:
                        cve_dict[cve_id].append(vuln_file)
                    else:
                        cve_dict[cve_id] = [vuln_file]

                output_list = []

                for cve_id, vuln_files in cve_dict.items():
                    if len(vuln_files) == 1:
                        vuln_file = vuln_files[0]
                    else:

                        vuln_file = max(vuln_files, key = lambda x: ast_sim_dict[x])
                        
                    if ast_sim_dict[vuln_file] > ast_sim_threshold_max and vuln_file not in near_sims_list:
                        
                        vulnerable_func_queue.put((code, dst_file, [vuln_file]))
                    else:
                       
                        output_list.append(vuln_file)
                        
            else:
                new_output_list = []
                for vuln_file in output_list:
                    if ast_sim_dict[vuln_file] > ast_sim_threshold_max and vuln_file not in near_sims_list:
                      
                        vulnerable_func_queue.put((code, dst_file, [vuln_file]))
                    else:
                       
                        new_output_list.append(vuln_file)
                output_list = new_output_list
                        
                
        return output_list != [], output_list

    except Exception as e:
        traceback.print_exc()
        raise Exception(f"error when process file {dst_file} : {str(e)}")
