import re
import networkx as nx
from html import unescape



class CFGExtractor:
    def __init__(self, filename, merge_node=True):
        self.filename = filename
        self.parse_cfg_file()

        if merge_node:
            self.merge_nodes()

    def parse_label(self, label):
        match = re.match(r"\((.+?),(.+)\)\<SUB\>(\d+)\</SUB\>", label)
        if match:
            method_full_name = unescape(match.group(1).strip())
            code = unescape(match.group(2).strip())

            if method_full_name == "RETURN":
                # code = code.split(",")[-1]
                code = code[: int(len(code) / 2)]

            line_number = int(match.group(3))
            return method_full_name, code, line_number
        else:
            return None, None, None

    def parse_cfg_file(self):
        with open(self.filename, "r") as file:
            content = file.read()

        node_pattern = re.compile(r'"([^"]+)" \[label = <(.+)> \]')
        edge_pattern = re.compile(r'  "([^"]+)" -> "([^"]+)"')

        nodes = {}
        edges = []

        for line in content.splitlines():
            match = node_pattern.match(line)
            if match:
                node_id = match.group(1)
                label = match.group(2)
                method_full_name, code, line_number = self.parse_label(label)
                
                # format code
                if code is not None:
                    code = code.replace("\n", " ") 
                    code = re.sub(r'\\012\s*', " ", code) 
                    code = code.replace('" "', " ")  
                    code = re.sub(r"\s+", " ", code) 
                    
                nodes[node_id] = {
                    "method_full_name": method_full_name,
                    "code": code,
                    "line_number": line_number,
                }

            match = edge_pattern.match(line)
            if match:
                source = match.group(1)
                target = match.group(2)
                edges.append((source, target))

        self.graph = nx.DiGraph()

        for node_id, data in nodes.items():
            self.graph.add_node(node_id, **data)

        for source, target in edges:
            if source == target:
                continue
            self.graph.add_edge(source, target)

    def merge_nodes(self):
        merged = True

        while merged:
            merged = False
         
            for node1, node2 in self.graph.edges():
               
                data1 = self.graph.nodes[node1]
                data2 = self.graph.nodes[node2]

               
                if data1["line_number"] == data2["line_number"]:
                   
                    last_node = node2
                    next_node = node2
                    while next_node in self.graph.successors(last_node):
                        last_node = next_node
                        next_node = list(self.graph.successors(last_node))[0]

                    
                    if self.graph.has_edge(node1, node2):
                     
                        for predecessor in self.graph.predecessors(node1):
                            if predecessor != last_node:
                                self.graph.add_edge(predecessor, last_node)

                      
                        for successor in self.graph.successors(node1):
                            if successor != last_node:
                                self.graph.add_edge(last_node, successor)

                        
                        nodes_to_remove = [node1]
                        next_node = node2
                        while next_node in self.graph.successors(last_node):
                            nodes_to_remove.append(next_node)
                            next_node = list(self.graph.successors(next_node))[0]

                        for node in nodes_to_remove:
                            self.graph.remove_node(node)

                        merged = True
                        break

    @property
    def node_dict(self):
        """
        line_number : code

        example:
        {
            '6': 'len = strlen(str)',
            '14': 'len = *ar + len | is_privileged(user)',
            '15': 'memcpy(buf, str, len)',
            '16': 'ar = malloc(sizeof(str))',
            '17': 'return process(ar, buf, len);',
            '7': '!is_privileged(user)',
            '8': 'clear(str)',
            '9': 'user++',
            '3': 'void'
        }
        """
        code_dict = {}

        nodes = self.graph.nodes(data=True)
        for node, data in nodes:
            line_number = data["line_number"]
            code = data["code"]

            if line_number and code:
                code_dict[line_number] = code

        return code_dict

    def dump(self, filename):
        nx.draw(self.graph, with_labels=True)

        import matplotlib.pyplot as plt

        plt.savefig(filename)


class CFPExtractor:
    def __init__(self, cfg_graph):
        self.cfg_graph = cfg_graph
        self.cfps = []
        self.extract_cfps()
        self.extract_lines()

        self.count = 0

    def find_all_paths_basic(self, graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return [path]
        if not graph.has_node(start):
            return []
        paths = []
        for neighbor in graph.neighbors(start):
            if neighbor not in path:
                new_paths = self.find_all_paths_basic(graph, neighbor, end, path)
                for new_path in new_paths:
                    paths.append(new_path)
        return paths

    def find_all_paths(self, graph, start, end, path=[], visited=[]):
        path = path + [start]
        visited = visited + [(start, path[-2] if len(path) > 1 else None)]

        if start == end:
            return [path]

        paths = []

        for node in graph[start]:
            if (node, start) not in visited:
                newpaths = self.find_all_paths(graph, node, end, path, visited)
                for newpath in newpaths:
                    paths.append(newpath)

        return paths

    def extract_cfps(self):
    
        entry_node = None
        exit_node = None
        for node, node_info in self.cfg_graph.nodes(data=True):
            if node_info["method_full_name"] == "METHOD":
                entry_node = node
            elif node_info["method_full_name"] == "METHOD_RETURN":
                exit_node = node
            if entry_node and exit_node:
                break

       
        self.paths = self.find_all_paths(self.cfg_graph, entry_node, exit_node)

    def extract_lines(self):
        for path in self.paths:
            cfp = []
            for node in path:
                node_info = self.cfg_graph.nodes[node]
                if (
                    cfp == []
                    or cfp[len(cfp) - 1]["line_number"] != node_info["line_number"]
                ):
                    cfp.append(node_info)
                else:
                    cfp[len(cfp) - 1] = node_info

            cfp = cfp[1:-1]
            self.cfps.append(cfp)

    def __str__(self):
        s = ""
        for cfp in self.cfps:
            for n in cfp:
                s += str(n["line_number"]) + " "
            s += "\n"
        return s

    def __iter__(self):
        return self

    def __next__(self):
        if self.count < len(self.cfps):
            result = self.cfps[self.count]
            self.count += 1
            return result
        else:
            raise StopIteration
