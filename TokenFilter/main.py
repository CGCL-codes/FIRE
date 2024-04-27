from multiprocessing import Pool
from functools import partial
import TokenFilter.token_extraction
import os
import config

VulTokens = []

def initialization(vul_functions):
    # Find Threshold Parse
    global VulTokens
    pool = Pool(5)
    VulTokens = pool.map(partial(TokenFilter.token_extraction.get_fea), vul_functions)
    VulTokens = list(filter(None, VulTokens))


def detect(code: str) -> tuple[bool, list[str]]:
    if VulTokens:
        is_vul = False
        tokens = TokenFilter.token_extraction.get_fea_code(code)
        vuln_list = []
        for vulnandtokens in VulTokens:
            vuln = TokenFilter.token_extraction.get_similarity(tokens, config.jaccard_sim_threshold, vulnandtokens)
            if vuln:
                vuln_list.append(vuln)
        # pool = Pool(5)
        # vuln_list = pool.map(partial(TokenFilter.token_extraction.get_similarity, tokens, 0.65), VulTokens)
        vuln_list = list(filter(None, vuln_list))
        if vuln_list:
            is_vul = True
        return is_vul, vuln_list
    else:
        raise Exception("Token Filter Not Initialized")


if __name__ == "__main__":

    forderpath = 'path/to/old/new/funcs'
    vuln_list = [] 

    for path, dir, files in os.walk(forderpath):
        for file in files:
            if file.split('_')[-1] == 'OLD.vul':
                filePath = os.path.join(path, file)
                vuln_list.append(filePath)
    print(len(vuln_list))

    initialization(vuln_list)
    print(VulTokens[0])
    a = detect('void InstructionSelector::AddInstruction(Instruction* instr) {\n  if (FLAG_turbo_instruction_scheduling &&\n      InstructionScheduler::SchedulerSupported()) {\n    DCHECK_NOT_NULL(scheduler_);\n    scheduler_->AddInstruction(instr);\n  } else {\n    sequence()->AddInstruction(instr);\n  }\n}\n')
    print(a)
