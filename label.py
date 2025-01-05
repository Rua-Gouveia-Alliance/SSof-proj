import copy

# Identifica a integridade da informação de um certo resource (variável?). A integridade é dada pelos sources que contaminaram
# a informação e os sanitizers por onde a informação passou desde o seu flow de cada source. 
class Label:
    def __init__(self, taints: list = None):
        # Set of tuples in the form ((source_name, source_line), (sanitizer_name, sanitizer_line) | None)
        self._taints = taints if taints is not None else list()
    
    def add_source(self, source: str, line: int):
        self._taints.append(((source, line), []))

    def add_sanitizer(self, sanitizer: str, line: int):
        for (_, sanitizers) in self._taints:
            sanitizers.append((sanitizer, line))
    
    def add_taint(self, taint):
        self._taints.append(taint)
    
    def get_taints(self):
        return self._taints

    def set_taints(self, taints):
        self._taints = taints
    
    def __add__(self, l: "Label"):
        # Creates a copy as to not modify the original label
        new_label = self.copy()
        l_taints = l.get_taints()

        for taint in l_taints:
            if taint not in self._taints:
                new_label.add_taint(taint)

        return new_label

    # copy() suffices as there are no mutable objects in the set    
    def copy(self):
        return Label(copy.deepcopy(self._taints))
    
    def __str__(self):
        return str(list(self._taints))


if __name__ == "__main__":
    l1 = Label()
    l2 = Label()

    l1.add_source("x", 1)
    l1.add_source("y", 2)
    l1.add_sanitizer("s1", 3)
    l1.add_source("z", 4)
    l1.add_sanitizer("s2", 5)
    print("L1")
    print(l1)
    print()

    l2.add_source("y", 2)
    l2.add_sanitizer("s1", 3)
    l2.add_sanitizer("s2", 5)
    l2.add_source("x", 1)
    print("L2")
    print(l2)
    print()

    l3 = l1 + l2
    print("L3")
    print(l3)
    print()