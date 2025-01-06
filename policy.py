from pattern import Pattern
from multilabel import MultiLabel

class Policy:
    def __init__(self, patterns: list = None):
        self._patterns = patterns if patterns != None else []
    
    def get_patterns(self):
        return self._patterns

    def get_vuln_names(self):
        return [pattern.get_name() for pattern in self._patterns]
    
    # Check if patterns or patterns' names should be returned
    def get_patterns_with_source(self, source:str):
        return [pattern.get_name() for pattern in self._patterns if pattern.check_if_source(source)]
    
    def get_patterns_with_sanitizer(self, sanitizer:str):
        return [pattern.get_name() for pattern in self._patterns if pattern.check_if_sanitizer(sanitizer)]
    
    def get_patterns_with_sink(self, sink:str):
        return [pattern.get_name() for pattern in self._patterns if pattern.check_if_sink(sink)]
    
    def get_sink_multilabel(self, sink:str, ml:MultiLabel):
        patterns_with_sink = self.get_patterns_with_sink(sink)
        return ml.filter_patterns(patterns_with_sink)

if __name__ == "__main__":
    print("TODO: Needs testing")    
