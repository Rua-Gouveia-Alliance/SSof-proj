from multilabel import MultiLabel


class Vulnerabilities:
    # Vulnerabilities is a dictionary where vulnerabilits' names are the keys
    # and the values are all relevant info on the illegal flows that were found
    def __init__(self, vuln_names: list):
        self._vulnerabilities = dict()
        for name in vuln_names:
            self._vulnerabilities[name] = []

    # Assuming the multilabel was already filtered to only contain the labels
    # with sink in its pattern
    # TODO: extract all vulnerabilities from the multilabel
    def store_vulnerabilities(self, ml: "MultiLabel", sink: tuple):
        for pattern, label in ml.get_mapping():
            if [label["explicit"], sink] in self._vulnerabilities[pattern.get_name()]:
                index = self._vulnerabilities[pattern.get_name()].index(
                    [label["explicit"], sink]
                )
                self._vulnerabilities[pattern.get_name()][index][0] += label["explicit"]
            else:
                self._vulnerabilities[pattern.get_name()].append(
                    [label["explicit"].copy(), sink]
                )

            if [label["implicit"], sink] in self._vulnerabilities[
                pattern.get_name()
            ] and pattern.is_implicit():
                index = self._vulnerabilities[pattern.get_name()].index(
                    [label["implicit"], sink]
                )
                self._vulnerabilities[pattern.get_name()][index][0] += label["implicit"]
            elif pattern.is_implicit():
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

                    # TODO: Fix bug in Label so that flows with same source/sink
                    # are grouped in list of lists of sanitizers
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
