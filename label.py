# Identifica a integridade da informação de um certo resource (variável?). A integridade é dada pelos sources que contaminaram
# a informação e os sanitizers por onde a informação passou desde o seu flow de cada source. 
class Label:
    def __init__(self, sources: set = None, sanitizers: set = None):    
        self._sources = set(sources) if sources is not None else set()               # List of strings with name of sources
        self._sanitizers = set(sanitizers) if sanitizers is not None else set()      # List of strings with name of sanitizers
    
    def add_source(self, source: str):
        self._sources.add(source)
    
    def add_sanitizer(self, sanitizer: str):
        self._sanitizers.add(sanitizer)
        
    def get_sources(self) -> set:
        return self._sources.copy()
    
    def set_sources(self, sources: set):
        self._sources = set(sources)
    
    def get_sanitizers(self) -> set:
        return self._sanitizers.copy()
    
    def set_sanitizers(self, sanitizers: set):
        self._sanitizers = set(sanitizers)
    
    # Adição de duas labels, que "junta" os seus níveis de integridade
    # Garante que a nova label criada é independente das outras 2 (com o uso de cópias)
    def __add__(self, l: "Label"):
        new_sources = self._sources.union(l.get_sources())
        new_sanitizers = self._sanitizers.union(l.get_sanitizers())
        
        return Label(new_sources, new_sanitizers)
    
    def copy(self):
        return Label(self._sources.copy(), self._sanitizers.copy())
    
    def __str__(self):
        return f"Sources: {list(self._sources)}\nSanitizers: {list(self._sanitizers)}"
