from pattern import Pattern
from label import Label


# TODO: Need to check if these multilabels should be independent from eachother due to __add__
# Grouping of various labels, such that each label corresponds to a pattern in a
# 1:1 correspondence
class MultiLabel:
    # _labels -> set of labels that keep integrity of resource in respect to a
    # pattern
    def __init__(self, patterns: list = [], is_context: bool = False):
        self._is_context = is_context
        self._labels = dict()
        for pattern in patterns:
            self._labels[pattern] = dict()
            self._labels[pattern]["explicit"] = Label(False)
            self._labels[pattern]["implicit"] = Label(True)

    def is_context(self):
        return self._is_context

    def get_mapping(self):
        return self._labels.items()

    def get_patterns(self):
        return self._labels.keys()

    def get_label_pair(self, pattern: Pattern):
        labels = self._labels.get(pattern, dict())

        if "explicit" not in labels:
            labels["explicit"] = Label(False)
        if "implicit" not in labels:
            labels["implicit"] = Label(True)

        return labels

    def set_label_pair(self, pattern: Pattern, labels: dict):
        self._labels[pattern] = dict()
        if self._is_context:
            # All labels stored in the context are implicit
            explicit = labels["explicit"].copy()
            explicit._implicit = True
            self._labels[pattern]["implicit"] = labels["implicit"] + explicit
            self._labels[pattern]["explicit"] = Label(False)
        else:
            self._labels[pattern]["implicit"] = labels["implicit"].copy()
            self._labels[pattern]["explicit"] = labels["explicit"].copy()

    def add_source(self, source: str, line: int):
        for pattern, label in self._labels.items():
            if pattern.check_if_source(source):
                label["explicit"].add_source(source, line)

    def add_sanitizer(self, sanitizer: str, line: int):
        for pattern, labels in self._labels.items():
            if pattern.check_if_sanitizer(sanitizer):
                labels["explicit"].add_sanitizer(sanitizer, line)
                labels["implicit"].add_sanitizer(sanitizer, line)

    def add_source_to_all(self, var_name, line):
        for label in self._labels.values():
            label["explicit"].add_source(var_name, line)

    def filter_patterns(self, patterns_names: list):
        ml = MultiLabel(is_context=self._is_context)
        patterns = self.get_patterns()

        for pattern_name in patterns_names:
            for pattern in patterns:
                if pattern_name == pattern.get_name() and (
                    len(self._labels[pattern]["explicit"].get_taints()) > 0
                    or len(self._labels[pattern]["implicit"].get_taints()) > 0
                ):
                    ml.set_label_pair(pattern, self._labels[pattern])
        return ml

    def copy(self):
        # Patterns do not need to be copied as they wont be chaned throughtout the program I think
        ml = MultiLabel(self.get_patterns())

        for pattern, labels in self._labels.items():
            ml.set_label_pair(pattern, labels)

        return ml

    def __add__(self, ml: "MultiLabel"):
        new_ml = MultiLabel(is_context=self._is_context)

        for pattern in self._labels:
            pair = dict()
            labels = ml.get_label_pair(pattern)
            pair["explicit"] = self._labels[pattern]["explicit"] + labels["explicit"]
            pair["implicit"] = self._labels[pattern]["implicit"] + labels["implicit"]
            new_ml.set_label_pair(pattern, pair)

        for pattern in ml.get_patterns():
            if pattern not in self._labels:
                new_ml.set_label_pair(pattern, ml.get_label_pair(pattern))

        return new_ml

    def __str__(self):
        string = ""

        for pattern, labels in self._labels.items():
            string += (
                pattern.get_name()
                + ":\n"
                + "Explicit Labels: "
                + str(labels["explicit"])
                + "\n"
                + "Implicit Labels: "
                + str(labels["implicit"])
                + "\n"
            )
        return string
