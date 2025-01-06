import copy

class Label:
    def __init__(self, taints: dict = None):
        # Each key is a tuple (source_name, source_line) and each value is a list of lists of tuples (sanitizer_name, sanitizer_line).
        # Each inner list corresponds to a unique flow
        self._taints = taints if taints is not None else dict()
    
    def add_source(self, source: str, line: int):
        if (source, line) in self._taints:
            self._taints[(source, line)].append([])
        else:
            self._taints[(source, line)] = [[]]

    def add_sanitizer(self, sanitizer: str, line: int):
        for sanitizer_flows in self._taints.values():
            for sanitizer_flow in sanitizer_flows:
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

        return new_label

    def copy(self):
        return Label(copy.deepcopy(self._taints))

    def __str__(self):
        return str(list(self._taints.items()))
