import copy

class Label:
    def __init__(self, implicit: bool, taints: dict = None):
        # Each key is a tuple (source_name, source_line) and each value is a
        # list of lists of tuples (sanitizer_name, sanitizer_line).
        # Each inner list corresponds to a unique flow
        self._implicit = implicit
        self._taints = taints if taints is not None else dict()

    def is_implicit(self):
        return self._implicit

    def add_source(self, source: str, line: int):
        if (source, line) in self._taints:
            self._taints[(source, line)].append([])
        else:
            self._taints[(source, line)] = [[]]

    def add_sanitizer(self, sanitizer: str, line: int):
        for sanitizer_flows in self._taints.values():
            for sanitizer_flow in sanitizer_flows:
                if (sanitizer, line) not in sanitizer_flow:
                    sanitizer_flow.append((sanitizer, line))

    def add_taint(self, source, sanitizer_flows):
        if source in self._taints:
            for sanitizer_flow in sanitizer_flows:
                if sanitizer_flow not in self._taints[source]:
                    self._taints[source].append(sanitizer_flow)
        else:
            self._taints[source] = sanitizer_flows

    def get_taints(self):
        return self._taints

    def set_taints(self, taints):
        self._taints = taints

    def __add__(self, l: "Label"):
        # Creates a copy as to not modify the original label
        new_label = self.copy()
        l_taints = l.get_taints()

        for l_source, l_flows in l_taints.items():
            new_label.add_taint(l_source, l_flows)

        new_label._implicit = False
        if (self._implicit and len(self._taints.keys()) > 0) or (
            l.is_implicit() and len(l.get_taints().keys()) > 0
        ):
            new_label._implicit = True

        return new_label

    def __eq__(self, other):
        return other.get_taints().keys() == self._taints.keys()

    def copy(self):
        return Label(self._implicit, copy.deepcopy(self._taints))

    def __str__(self):
        return str(list(self._taints.items()))
