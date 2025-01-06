from multilabel import MultiLabel
from label import Label


class Vulnerabilities:
    # Vulnerabilities is a dictionary where vulnerabilits' names are the keys and the values are all relevant info on the illegal flows that were found
    def __init__(self, vuln_names: list):
        self._vulnerabilities = dict()
        for name in vuln_names:
            self._vulnerabilities[name] = []

    # Assuming the multilabel was already filtered to only contain the labels with sink in its pattern
    # TODO: extract all vulnerabilities from the multilabel
    def store_vulnerabilities(self, ml: "MultiLabel", sink: tuple):
        for pattern, label in ml.get_mapping():
            self._vulnerabilities[pattern.get_name()].append((label, sink))

    def get_json(self):
        json = []
        for vuln_name, labels in self._vulnerabilities.items():
            i = 1
            for label, sink in labels:
                for source, sanitizer_flows in label.get_taints().items():
                    vuln = dict()

                    vuln["vulnerability"] = vuln_name + "_" + str(i)
                    vuln["source"] = list(source)
                    vuln["sink"] = list(sink)

                    # TODO: Change this when implicit flows are implemented
                    vuln["implicit_flows"] = False

                    # TODO: Fix bug in Label so that flows with same source/sink are grouped in list of lists of sanitizers
                    vuln["unsanitized_flows"] = [] in sanitizer_flows

                    without_unsanitized = [
                        [list(sanitizer) for sanitizer in sanitizer_flow]
                        for sanitizer_flow in sanitizer_flows
                        if sanitizer_flow
                    ]
                    vuln["sanitized_flows"] = without_unsanitized
                    json.append(vuln)

        return json
