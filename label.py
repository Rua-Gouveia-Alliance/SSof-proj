# Identifica a integridade da informação de um certo resource (variável?). A integridade é dada pelos sources que contaminaram
# a informação e os sanitizers por onde a informação passou desde o seu flow de cada source. 
class Label:
    def __init__(self, sources: set = None, sanitizers: set = None):    
        self._sources = sources if sources is not None else set()               # List of strings with name of sources
        self._sanitizers = sanitizers if sanitizers is not None else set()      # List of strings with name of sanitizers
    
    def add_source(self, source: str):
        self._sources.add(source)
    
    def add_sanitizer(self, sanitizer: str):
        self._sanitizers.add(sanitizer)
        
    def get_sources(self):
        return self._sources.copy()
    
    def set_sources(self, sources: list):
        self._sources = sources
    
    def get_sanitizers(self):
        return self._sanitizers.copy()
    
    def set_sanitizers(self, sanitizers):
        self._sanitizers = sanitizers
    
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

"""
l1 = Label()
l2 = Label()

l1.add_source("x")
l1.add_source("y")
l1.add_source("z")
l1.add_sanitizer("s1")
print(l1.get_sources())
print(l1.get_sanitizers())

l2.add_source("x")
l2.add_source("y")
l2.add_sanitizer("s2")
l2.add_sanitizer("s3")
print(l2.get_sources())
print(l2.get_sanitizers())

l3 = l1 + l2

print(l3.get_sources())
print(l3.get_sanitizers())

print()
print(l1.get_sources())
print(l1.get_sanitizers())
print()
print(l2.get_sources())
print(l2.get_sanitizers())
"""