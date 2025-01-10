from src.multilabel import MultiLabel

class MultiLabelling:
    # Dictionary with strings as keys (representing variables) and multilabel as values
    def __init__(self, ml: dict = None):
        self._var_labels = ml if ml is not None else dict()

        # Keeps track of names that might not be initialized on at least one flow of the program
        self._not_initialized = set()

    def get_var_labels(self):
        return self._var_labels

    def get_varnames(self):
        return self._var_labels.keys()

    def get_not_initialized(self):
        return self._not_initialized

    def set_not_initialized(self, not_initiazized: set):
        self._not_initialized = not_initiazized

    def add_to_not_initialized(self, value: str):
        self._not_initialized.add(value)

    def merge_not_initialized(self, other: set):
        self._not_initialized = self._not_initialized.union(other)

    def has_not_initialized_flow(self, var_name: str):
        return var_name in self._not_initialized

    def is_defined(self, var_name: str):
        return var_name in self._var_labels.keys()

    def get_multilabel(self, var_name: str):
        return self._var_labels.get(var_name, MultiLabel()).copy()

    # define Multilabel.copy
    def set_multilabel(self, var_name: str, ml: MultiLabel, from_assignment=True):
        self._var_labels[var_name] = ml.copy()

        if from_assignment:
            self._not_initialized.discard(var_name)

    def update_multilabel(self, var_name: str, ml: MultiLabel):
        self._var_labels[var_name] = (
            ml.copy() + self._var_labels.get(var_name, MultiLabel()).copy()
        )

    def copy(self):
        new_multilabelling = MultiLabelling()

        for var, multilabel in self._var_labels.items():
            new_multilabelling.set_multilabel(var, multilabel, False)

        new_multilabelling.set_not_initialized(self.get_not_initialized())

        return new_multilabelling

    # Combinor adds
    def __add__(self, other):
        new_multilabelling = self.copy()

        for var_name, multilabel in new_multilabelling.get_var_labels().items():
            if not other.is_defined(var_name):
                new_multilabelling.add_to_not_initialized(var_name)

            new_multilabelling.set_multilabel(
                var_name, multilabel + other.get_multilabel(var_name), False
            )

        for var_name in other.get_varnames():
            if var_name not in new_multilabelling.get_varnames():
                new_multilabelling.add_to_not_initialized(var_name)

                new_multilabelling.set_multilabel(
                    var_name, other.get_multilabel(var_name), False
                )

        new_multilabelling.merge_not_initialized(other.get_not_initialized())

        return new_multilabelling

    def __str__(self):
        string = ""
        for var, ml in self._var_labels.items():
            string += var + " " + str(ml)
        string += str(self._not_initialized) + "\n"
        return string


if __name__ == "__main__":
    print("TODO: Needs testing")
