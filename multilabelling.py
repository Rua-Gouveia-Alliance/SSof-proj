from multilabel import MultiLabel

class MultiLabelling:
    # Dictionary with strings as keys (representing variables) and multilabel as values 
    def __init__(self, ml:dict = None):
        self._var_lables = ml if ml is not None else dict()
    
    def get_varnames(self):
        return self._var_lables.keys()

    # define Multilabel.copy
    def get_multilabel(self, var_name:str):
        return self._var_lables.get(var_name, MultiLabel()).copy()
    
    # define Multilabel.copy
    def set_multilabel(self, var_name:str, ml:MultiLabel):
        self._var_lables[var_name] = ml.copy()
    
    def update_multilabel(self, var_name:str, ml:MultiLabel):
        self._var_lables[var_name] = ml.copy() + self._var_lables.get(var_name, MultiLabel()).copy()
    
    def copy(self):
        new_multilabelling = MultiLabelling()

        for var, multilabel in self._var_lables.items():
            new_multilabelling.set_multilabel(var, multilabel)
        
        return new_multilabelling
    
    # Combinor adds
    def __add__(self, other):
        new_multilabelling = self.copy()

        for var_name, multilabel in self._var_lables.items():
            new_multilabelling.set_multilabel(var_name, multilabel + other.get_multilabel(var_name))
        
        for var_name in other.get_varnames():
            if var_name not in self._var_lables.keys():
                new_multilabelling.set_multilabel(var_name, other.get_multilabel(var_name))
        
        return new_multilabelling
        
        

if __name__ == "__main__":
    print("TODO: Needs testing")
