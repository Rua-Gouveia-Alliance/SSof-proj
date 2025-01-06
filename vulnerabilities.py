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
    
    def print_vulnerability(self, vuln_name: str):
        for vuln in self._vulnerabilities[vuln_name]:
            sources, sanitizers, sink = vuln

            if len(sanitizers) == 0:
                print(f"Serious vulnerability!\nInformation originating from {sources} reaches {sink} without any sanitization!")
            else:
                print(f"Warning!\nInformation originating from {sources} reaches {sink} but goes through some sanitizers {sanitizers}!")

    def get_json(self):
        json = []
        for vuln_name, labels in self._vulnerabilities.items():
            i = 1
            for (label, sink) in labels:
                vuln = dict()
                sanitizers = [list(sanitizer) for sanitizer in label[1]]

                vuln["vulnerability"] = vuln_name
                vuln["source"] = list(label[0])
                vuln["sink"] = list(sink)

                # TODO: Change this when implicit flows are implemented
                vuln["implicit_flows"] = False

                # TODO: Fix bug in Label so that flows with same source/sink are grouped in list of lists of sanitizers
                vuln["unsanitized_flows"] = sanitizers != []
                vuln["sanitized_flows"] = sanitizers


                

    def __str__(self):
        out = ""
        for vuln, labels in self._vulnerabilities.items():
            out += "VULNERABILITY " + vuln + "\n"
            for (label, sink) in labels:
                out += "\t" + str(label) + " " + str(sink) + "\n"
        return out

if __name__ == "__main__":
    print("TODO: Needs testing")