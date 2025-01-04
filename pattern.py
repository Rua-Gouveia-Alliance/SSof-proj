class Pattern:
    def __init__(self, vuln_name: str, sources: list = None, sanitizers: list = None, sinks: list = None):
        self._vuln_name = vuln_name
        self._sources = sources if sources is not None else []
        self._sanitizers = sanitizers if sanitizers is not None else []
        self._sinks = sinks if sinks is not None else []
    
    def get_name(self):
        return self._vuln_name
    
    def get_sources(self):
        return self._sources.copy()
    
    def set_sources(self, sources: list):
        self._sources = sources

    def get_sanitizers(self):
        return self._sanitizers.copy()
    
    def set_sanitizers(self, sanitizers: list):
        self._sanitizers = sanitizers
    
    def get_sinks(self):
        return self._sinks.copy()
    
    def set_sinks(self, sinks: list):
        self._sinks = sinks
    
    def check_source(self, source: str):
        return source in self._sources
    
    def check_sanitizer(self, sanitizer: str):
        return sanitizer in self._sanitizers
    
    def check_sink(self, sink: str):
        return sink in self._sinks
    
    def check_name(self, name: str):
        hits = []
        if name in self._sources:
            hits.append("source")
        
        if name in self._sanitizers:
            hits.append("sanitizer")
        
        if name in self._sinks:
            hits.append("sink")

        return hits
    
    def check_if_source(self, name: str):
        return name in self._sources
    
    def check_if_sanitizer(self, name: str):
        return name in self._sanitizers
    
    def check_if_sink(self, name: str):
        return name in self._sinks
    
    def __str__(self):
        return f"Vulnerability: {self._vuln_name}\nSources: {self._sources}\nSanitizers: {self._sanitizers}\nSinks: {self._sinks}"
    
    # This considers that two different vulnerabilities cannot have the same name and different characteristics
    def __eq__(self, p):
        return self._vuln_name == p.get_name()
    
    def __hash__(self):
        return hash(self._vuln_name)

if __name__ == "__main__":
    p = Pattern("bad_vulnerability", ["x", "y"], ["s1"], ["a", "b"])

    print(p.get_name())
    print(p.check_source("x"))
    print(p.check_source("z"))
    print(p.check_name("x"))
    print(p)