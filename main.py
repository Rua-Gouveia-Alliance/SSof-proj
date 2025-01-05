import sys
import esprima
import json
from copy import deepcopy
from multilabel import MultiLabel
from pattern import Pattern


def usage():
    print("Usage: main <program_file> <patterns_file>")


def print_ast(currobj, indent):
    print(
        " " * 4 * indent
        + "Type: "
        + currobj.get("type", "Unknown")
        + ", line "
        + str(currobj.get("loc", {}).get("start", {}).get("line", "Unknown"))
    )

    for key, val in currobj.items():
        if key == "loc":
            continue
        elif type(val) is list:
            for obj in val:
                print_ast(obj, indent + 1)
        elif type(val) is dict:
            print_ast(val, indent + 1)


# Not working since this function was developed for the Python AST
# Use this as a stepping stone to develop walk_expression and walk_statement
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
        for i in range(1, max_depth + 1):
            thiscyclepaths = deepcopy(currpaths)
            for j in range(i):
                for path in thiscyclepaths:
                    path.append((currtype, currobj.get("lineno", -1)))
                for obj in currobj["body"]:
                    thiscyclepaths = get_ast_paths(thiscyclepaths, obj)
            paths.extend(thiscyclepaths)
        return paths


# TODO: returns Multilabel
def walk_expression(expr, policy, multilabelling, vulnerabilities):
    expr_type = expr["type"]

    if expr_type == "Literal":
        # A literal has the lowest possible integrity for all patterns
        return MultiLabel()
    elif expr_type == "Identifier":
        var_name = expr["name"]
        line = expr["loc"]["start"]["line"]

        # If variable is instantiated fetch its multilabel and add it as a source to the patterns where the variable is considered a source
        if multilabelling.is_defined(var_name):
            ml = multilabelling.get_multilabel(var_name)
            ml.add_source(var_name, line)
        # If the variable is not instantiated it has to be considered a source in every possible pattern
        else:
            ml = MultiLabel()
            ml.add_source_to_all(var_name, line)

        return ml
    elif expr_type == "UnaryExpression":
        
        return MultiLabel()
    elif expr_type == "BinaryExpression":
        return MultiLabel()
    elif expr_type == "CallExpression":
        return MultiLabel()
    elif expr_type == "MemberExpression":
        return MultiLabel()
    elif expr_type == "AssignmentExpression":
        return MultiLabel()
    else:
        return MultiLabel()


# TODO: returns Multilabelling
def walk_statement(expr, policy, multilabelling, vulnerabilites):
    return


def load_patterns(filename):
    with open(filename, "r") as f:
        content = f.read()

    p_dict = json.loads(content)
    patterns = []

    for pattern in p_dict:
        vuln = pattern.get("vulnerability", "NO NAME")
        sources = pattern.get("sources", [])
        sanitizers = pattern.get("sanitizers", [])
        sinks = pattern.get("sinks", [])
        implicit = False if pattern.get("implicit", "no") == "no" else True
        patterns.append(Pattern(vuln, sources, sanitizers, sinks, implicit))
        print(Pattern(vuln, sources, sanitizers, sinks, implicit))


def extract_ast(filename):
    with open(filename, "r") as f:
        program = f.read()

    ast_dict = esprima.parseScript(program, loc=True).toDict()
    return json.dumps(ast_dict, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
        exit(1)
    js_file = sys.argv[1]
    patterns_file = sys.argv[2]

    ast = extract_ast(js_file)
    print(ast)
    patterns = load_patterns(patterns_file)
