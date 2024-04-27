
import json


class TaintFlowExtractor:
    
    def __init__(self, taint_file, taint_min_len=2) -> None:
        self.taint_file = taint_file
        self.taint_min_len = taint_min_len
        with open(self.taint_file, "r") as f:
            data = json.load(f)
        
        self.taint_flows = []
        for item in data:
            taint_flow = item.get("elements", {})
            self.taint_flows.append(taint_flow)
            
        self._taint_line_flows = None

    @property
    def taint_line_flows(self):
        if self._taint_line_flows is None:
            self._taint_line_flows = []
            for taint_flow in self.taint_flows:
                line_flow = []
                for node in taint_flow:
                    if not line_flow or line_flow[len(line_flow)-1] != node["lineNumber"]:
                        line_flow.append(node["lineNumber"])

                if line_flow and len(line_flow) >= self.taint_min_len and line_flow not in self._taint_line_flows:
                    self._taint_line_flows.append(line_flow)
                
            self._taint_line_flows = sorted(self._taint_line_flows, key=lambda x: x[0])
        
        return self._taint_line_flows
         