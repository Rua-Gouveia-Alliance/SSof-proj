from pattern import Pattern
from label import Label


# TODO: Need to check if these multilabels should be independent from eachother due to __add__
# Grouping of various labels, such that each label corresponds to a pattern in a 1:1 correspondence
class MultiLabel:
    # _labels -> set of labels that keep integrity of resource in respect to a pattern
    def __init__(self, patterns: list = []):
        self._labels = dict()
        for pattern in patterns:
            self._labels[pattern] = Label()

    # Only for debugging
    def get_mapping(self):
        return self._labels

    def get_patterns(self):
        return self._labels.keys()

    def get_labels(self):
        return self._labels.values()

    def get_label(self, pattern: Pattern):
        return self._labels.get(pattern, Label())

    def set_label(self, pattern: Pattern, label: Label):
        self._labels[pattern] = label.copy()

    def add_pattern(self, pattern: Pattern):
        self._labels[pattern] = Label()

    def add_source(self, source: str, line: int):
        for pattern, label in self._labels.items():
            if pattern.check_if_source(source):
                label.add_source(source, line)

    def add_sanitizer(self, sanitizer: str, line: int):
        for pattern, label in self._labels.items():
            if pattern.check_if_sanitizer(sanitizer):
                label.add_sanitizer(sanitizer, line)

    def filter_patterns(self, patterns_names: list):
        ml = MultiLabel()
        patterns = self.get_patterns()

        for pattern_name in patterns_names:
            for pattern in patterns:
                if pattern_name == pattern.get_name():
                    ml.set_label(pattern, self._labels[pattern])

        return ml

    def copy(self):
        # Patterns do not need to be copied as they wont be chaned throughtout the program I think
        ml = MultiLabel(self.get_patterns())

        for pattern, label in self._labels.items():
            ml.set_label(pattern, label)

        return ml

    def __add__(self, ml: "MultiLabel"):
        new_ml = MultiLabel()

        for pattern in self._labels:
            new_ml.set_label(pattern, self._labels[pattern] + ml.get_label(pattern))

        for pattern in ml.get_patterns():
            if pattern not in self._labels:
                new_ml.set_label(pattern, ml.get_label(pattern))

        return new_ml

    def __str__(self):
        string = ""

        for pattern, label in self._labels.items():
            string += pattern.get_name() + ":\n" + str(label) + "\n\n"

        return string


if __name__ == "__main__":
    p1 = Pattern("p1", ["a"], ["s1"])
    p2 = Pattern("p2", ["b", "c"], ["s2"])
    p3 = Pattern("p3", ["d"], ["s3"])
    ml1 = MultiLabel()
    ml2 = MultiLabel()

    ml1.add_pattern(p1)
    ml1.add_pattern(p2)
    ml2.add_pattern(p2)
    ml2.add_pattern(p3)

    ml1.add_source("a")
    ml1.add_source("b")
    ml1.add_sanitizer("s2")
    ml2.add_source("c")
    ml2.add_source("d")
    ml2.add_sanitizer("s3")

    print("ML1:")
    print(ml1)
    print("ML2:")
    print(ml2)
    print("ML1 + ML2")
    print(ml1 + ml2)
