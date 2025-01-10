import sys
import esprima
import json
import os
from copy import deepcopy
from multilabel import MultiLabel
from multilabelling import MultiLabelling
from pattern import Pattern
from policy import Policy
from vulnerabilities import Vulnerabilities


def usage():
    print("Usage: python js_analyser.py <program_file> <patterns_file>")


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


# TODO: Assumes sources/sanitizers/sinks are simple names without ".". We can
# try to augment it to consider these cases although it would only count as
# bonus work
def walk_expression(expr, policy, multilabelling, vulnerabilities, context):
    expr_type = expr["type"]

    if expr_type == "Literal":
        # A literal has the highest possible integrity for all patterns
        return MultiLabel()
    elif expr_type == "Identifier":
        var_name = expr["name"]
        line = expr["loc"]["start"]["line"]

        # If variable is instantiated fetch its multilabel and add it as a
        # source to the patterns where the variable is considered a source
        if multilabelling.is_defined(var_name):
            ml = multilabelling.get_multilabel(var_name)

            if multilabelling.has_not_initialized_flow(var_name):
                ml.add_source_to_all(var_name, line)
            else:
                ml.add_source(var_name, line)
        # If the variable is not instantiated it has to be considered a
        # source in every possible pattern
        else:
            if var_name not in policy.get_sanitizers():
                ml = MultiLabel(policy.get_patterns())
                ml.add_source_to_all(var_name, line)
            else:
                return MultiLabel()
        return ml
    elif expr_type == "UnaryExpression":
        return walk_expression(
            expr["argument"], policy, multilabelling, vulnerabilities, context
        )
    elif expr_type == "BinaryExpression":
        left = walk_expression(
            expr["left"], policy, multilabelling, vulnerabilities, context
        )
        right = walk_expression(
            expr["right"], policy, multilabelling, vulnerabilities, context
        )
        return left + right
    elif expr_type == "CallExpression":
        line = expr["loc"]["start"]["line"]

        # Get Multilabel of callee and callee name
        callee = expr["callee"]

        # CallExpressions of the form a()
        if callee["type"] == "Identifier":
            callee_name = callee["name"]
            callee_multilabel = MultiLabel(policy.get_patterns())
            callee_multilabel.add_source(callee_name, line)
        # CallExpressions of the form a.b.c()
        else:
            callee_name = callee["property"]["name"]
            callee_multilabel = walk_expression(
                expr["callee"]["object"],
                policy,
                multilabelling,
                vulnerabilities,
                context,
            )
            callee_multilabel.add_source(callee_name, line)

        # Get Multilabel of all arguments
        arg_multilabel = MultiLabel()
        for arg in expr["arguments"]:
            arg_multilabel += walk_expression(
                arg, policy, multilabelling, vulnerabilities, context
            )

        # If function is a sanitizer, apply the sanitizer to the arguments
        # multilabel
        arg_multilabel.add_sanitizer(callee_name, line)
        context.add_sanitizer(callee_name, line)

        # If function is a sink, store the vulnerabilities that the arguments
        # might pass
        arg_multilabel += context
        vulnerabilities.store_vulnerabilities(
            policy.get_vulnerabilities(callee_name, arg_multilabel),
            (callee_name, line),
        )

        return callee_multilabel + arg_multilabel
    elif expr_type == "MemberExpression":
        obj_multilabel = walk_expression(
            expr["object"], policy, multilabelling, vulnerabilities, context
        )
        prop_multilabel = walk_expression(
            expr["property"], policy, multilabelling, vulnerabilities, context
        )

        return obj_multilabel + prop_multilabel
    elif expr_type == "AssignmentExpression":
        assigned_name = get_expr_name(expr["left"])
        rhs_multilabel = walk_expression(
            expr["right"], policy, multilabelling, vulnerabilities, context
        )

        # Uncomment this if shenanigans such as "a.b().c = d" have to be
        # considered. If so, a way to speed up the program would be to skip
        # get_lhs skips and augment the Json nodes to store information if a
        # certain name is a sink or not. The higher level node will get that
        # information after visiting the child and augment it to its parent and
        # so on. The AssignmentExpression, in the end, will have a list of sinks
        # of the lhs.
        # walk_expression(expr["left"], policy, multilabelling, vulnerabilities)
        lhs_sinks = get_lhs_sinks(expr["left"], policy)
        rhs_multilabel += context

        for sink in lhs_sinks:
            vulnerabilities.store_vulnerabilities(
                policy.get_vulnerabilities(sink[0], rhs_multilabel), sink
            )

        # Update Multilabelling
        if assigned_name != "":
            multilabelling.set_multilabel(assigned_name, rhs_multilabel)

        # I might be missing something but the returned Multilabel might be
        # irrelevant in this case
        return MultiLabel()
    else:
        print("Unrecognized expression type: " + expr_type)
        return MultiLabel()


def get_expr_name(expr):
    expr_type = expr["type"]

    if expr_type == "Identifier":
        return expr["name"]
    elif expr_type == "MemberExpression":
        if expr["computed"]:
            return get_expr_name(expr["object"])
        return get_expr_name(expr["property"])
    else:
        print("Unrecognized expression type: " + expr_type)
        return ""


# In this function I am assuming that the left hand side of an assignment is
# either a single Identifier or a MemberExpression such as "a.b.c ..." or
# "a.b['test']". I am not considering shenanigans such as "a.b().c = d". If
# these have to be considered for some reason, one solution is to call
# walk_expression and augment the Json nodes to store information if a certain
# name is a sink or not. The higher level node will get that information after
# visiting the child and augment it to its parent and so on. The
# AssignmentExpression, in the end, will have a list of sinks of the lhs
def get_lhs_sinks(expr, policy):
    expr_type = expr["type"]

    if expr_type == "Identifier":
        line = expr["loc"]["start"]["line"]
        return (
            [(expr["name"], line)]
            if policy.get_patterns_with_sink(expr["name"])
            else []
        )
    elif expr_type == "MemberExpression":
        if expr["computed"]:
            return get_lhs_sinks(expr["object"], policy)
        return get_lhs_sinks(expr["object"], policy) + get_lhs_sinks(
            expr["property"], policy
        )
    else:
        print("Unrecognized left hand side expression type: " + expr_type)
        return []


def walk_statement(stmt, policy, multilabelling, vulnerabilities, context):
    stmt_type = stmt["type"]

    if stmt_type == "Program" or stmt_type == "BlockStatement":
        for s in stmt.get("body", []):
            multilabelling = walk_statement(
                s, policy, multilabelling, vulnerabilities, context
            )
        return multilabelling
    elif stmt_type == "ExpressionStatement":
        walk_expression(
            stmt["expression"], policy, multilabelling, vulnerabilities, context
        )

        return multilabelling
    elif stmt_type == "IfStatement":
        # Adding the condition to the analysis context
        cond = walk_expression(
            stmt["test"], policy, multilabelling, vulnerabilities, context
        )
        new_context = context + cond
        ml_copy = multilabelling.copy()

        # MultiLabelling of the "if" branch
        consequent = walk_statement(
            stmt["consequent"], policy, multilabelling, vulnerabilities, new_context
        )

        # Alternate is not always present
        alternate = (
            walk_statement(
                stmt["alternate"], policy, ml_copy, vulnerabilities, new_context
            )
            if "alternate" in stmt
            else ml_copy
        )

        return consequent + alternate
    elif stmt_type == "WhileStatement":
        # Adding the condition to the analysis context
        cond = walk_expression(
            stmt["test"], policy, multilabelling, vulnerabilities, context
        )
        new_context = context + cond

        prev_multilabelling = None
        cycle_multilabelling = multilabelling.copy()
        res_multilabelling = multilabelling.copy()
        while prev_multilabelling != cycle_multilabelling:
            prev_multilabelling = cycle_multilabelling.copy()
            cycle_multilabelling = walk_statement(
                stmt["body"], policy, cycle_multilabelling, vulnerabilities, new_context
            )
            res_multilabelling += cycle_multilabelling

        return res_multilabelling
    else:
        print("Unrecognized statement type: " + stmt_type)
        return MultiLabelling()


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

    return patterns


def extract_ast(filename):
    with open(filename, "r") as f:
        program = f.read()

    ast_dict = esprima.parseScript(program, loc=True).toDict()
    # print(json.dumps(ast_dict, indent=2))
    return ast_dict


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
        exit(1)
    js_file = sys.argv[1]
    patterns_file = sys.argv[2]

    ast = extract_ast(js_file)  # load ast
    patterns = load_patterns(patterns_file)  # load patterns
    policy = Policy(patterns)  # create policy from patterns

    # create multilabelling, vulnerabilities, and context instance
    multilabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities([pattern.get_name() for pattern in patterns])
    context = MultiLabel(is_context=True)

    # walk through all statements in the program
    walk_statement(ast, policy, multilabelling, vulnerabilities, context)

    # get output
    vulnerabilities_json = vulnerabilities.get_json()

    # save output
    os.makedirs("./output", exist_ok=True)
    output_file = os.path.join(
        "./output", f"{os.path.splitext(os.path.basename(js_file))[0]}.output.json"
    )
    with open(output_file, "w") as f:
        json.dump(vulnerabilities_json, f, indent=4)
