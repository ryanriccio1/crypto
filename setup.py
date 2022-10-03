from glob import glob
from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension

# add all cpp files to build
ext_modules = [
    Pybind11Extension(
        "cryptanalysis",
        sorted(glob("cryptanalysis/*.cpp")),  # Sort source files for reproducibility
    ),
]

# build module
setup(name='playfair_crack',
      version='1.0',
      description='Python package with playfair_crack C++ extension (PyBind11)',
      ext_modules=ext_modules)
