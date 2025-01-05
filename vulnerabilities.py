from multilabel import MultiLabel
from label import Label

class Vulnerabilities:
    # Vulnerabilities is a dictionary where vulnerabilits' names are the keys and the values are all relevant info on the illegal flows that were found
    def __init__(self):
        self._vulnerabilities = dict()

    # Assuming the multilabel was already filtered to only contain the labels with sink in its pattern
    # TODO: extract all vulnerabilities from the multilabel
    def store_vulnerabilities(self, ml:"MultiLabel", sink:str):
        vulns = self._vulnerabilities.get(vuln_name, [])

        for label in ml.get_labels():
            vulns.append((label.get_sources(), label.get_sanitizers(), sink))
        
        self._vulnerabilities[vuln_name] = vulns
    
    def print_vulnerability(self, vuln_name:str):
        for vuln in self._vulnerabilities[vuln_name]:
            sources, sanitizers, sink = vuln

            if len(sanitizers) == 0:
                print(f"Serious vulnerability!\nInformation originating from {sources} reaches {sink} without any sanitization!")
            else:
                print(f"Warning!\nInformation originating from {sources} reaches {sink} but goes through some sanitizers {sanitizers}!")

if __name__ == "__main__":
    print("TODO: Needs testing")