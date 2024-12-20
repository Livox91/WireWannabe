class SingletonMeta(type):
    """
    A metaclass for creating singleton classes.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class Config(metaclass=SingletonMeta):
    """
    A singleton configuration class.
    """
    def __init__(self):
        self._interface = None  # Initialize private attributes
        self._count = 0
        self._bpfFilter = None
        self._output_file = None
        pass
    @property
    def interface(self):
        return self._interface

    @interface.setter
    def interface(self, value):
        self._interface = value
    
    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        if isinstance(value, int) and value >= 0:
            self._count = value
        else:
            raise ValueError("Count must be a non-negative integer.")
    
    @property
    def bpfFilter(self):
        return self._bpfFilter

    @bpfFilter.setter
    def bpfFilter(self, value):
        self._bpfFilter = value

    
    @property
    def output_file(self):
        return self._output_file

    @output_file.setter
    def output_file(self, value):
        self._output_file = value    
