import sys
import ast
from astexport import export
import json
from copy import deepcopy

def usage():
    print("Usage: main <filename>")

def print_ast(currobj, indent):
    print(" " * 4 * indent + "Type: " + currobj["ast_type"] + ", line " + str(currobj.get("lineno", "-1")))
    for key, val in currobj.items():
        if type(val) is list:
            for obj in val:
                print_ast(obj, indent+1)
        elif type(val) is dict:
            print_ast(val, indent+1)


def get_ast_paths(paths, currobj):
    currtype = currobj["ast_type"]

    # This can be augmented to also print every constant and variable
    if currtype == "Module":
        for obj in currobj["body"]:
            paths = get_ast_paths(paths, obj)
        return paths
    elif currtype == "Assign":
        for path in paths:
            path.append((currtype, currobj.get("lineno", -1)))
        return paths
    elif currtype == "If":
        paths2 = deepcopy(paths)

        for path in paths:
            path.append((currtype, currobj.get("lineno", -1)))
        
        # TODO: Not completely correct as "lineno" gets number of line of if clause
        for path in paths2:
            path.append((currtype, currobj.get("lineno", -1)))
        
        for obj in currobj["body"]:
            paths = get_ast_paths(paths, obj)
        
        for obj in currobj["orelse"]:
            paths2 = get_ast_paths(paths2, obj)
        
        paths.extend(paths2)
        return paths
    elif currtype == "While":
        max_depth = 2
        currpaths = deepcopy(paths)
        for i in range(1, max_depth+1):
            thiscyclepaths = deepcopy(currpaths)
            for j in range(i):
                for path in thiscyclepaths:
                    path.append((currtype, currobj.get("lineno", -1)))
                for obj in currobj["body"]:
                    thiscyclepaths = get_ast_paths(thiscyclepaths, obj)
            paths.extend(thiscyclepaths)
        return paths

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    filename = sys.argv[1]
    text = open(filename).read()
    parsed_ast = ast.parse(text)
    ast_dict = export.export_dict(parsed_ast)
    #print(print_ast(ast_dict, 0))
    print(get_ast_paths([[]], ast_dict))
    #print(json.dumps(ast_dict, indent=2))
    