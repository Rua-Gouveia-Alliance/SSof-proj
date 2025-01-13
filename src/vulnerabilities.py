from src.multilabel import MultiLabel

class Vulnerabilities:
    # Vulnerabilities is a dictionary where vulnerabilits' names are the keys
    # and the values are all relevant info on the illegal flows that were found
    def __init__(self, vuln_names: list):
        self._vulnerabilities = dict()
        for name in vuln_names:
            self._vulnerabilities[name] = []

    def find_entry(self, pattern, label, sink):
        def same_sources(label1, label2):
            return label1.get_taints().keys() == label2.get_taints().keys()

        return next(
            (
                i
                for i, item in enumerate(self._vulnerabilities[pattern.get_name()])
                if item[1] == sink
            ),
            -1,
        )

    def store_vulnerabilities(self, ml: "MultiLabel", sink: tuple):
        for pattern, label in ml.get_mapping():
            index = self.find_entry(pattern, label["explicit"], sink)
            if index != -1:
                self._vulnerabilities[pattern.get_name()][index][0] += label["explicit"]
            else:
                self._vulnerabilities[pattern.get_name()].append(
                    [label["explicit"].copy(), sink]
                )

            if pattern.is_implicit():
                index = self.find_entry(pattern, label["implicit"], sink)
                if index != -1:
                    self._vulnerabilities[pattern.get_name()][index][0] += label[
                        "implicit"
                    ]
                else:
                    self._vulnerabilities[pattern.get_name()].append(
                        [label["implicit"].copy(), sink]
                    )

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

                    vuln["unsanitized_flows"] = "yes" if [] in sanitizer_flows else "no"

                    without_unsanitized = [
                        [list(sanitizer) for sanitizer in sanitizer_flow]
                        for sanitizer_flow in sanitizer_flows
                        if sanitizer_flow
                    ]
                    vuln["sanitized_flows"] = without_unsanitized
                    vuln["implicit"] = "yes" if label.is_implicit() else "no"

                    json.append(vuln)
                    i += 1

        return json
