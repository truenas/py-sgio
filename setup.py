from setuptools import setup
from Cython.Build import cythonize

setup(
    name='libsgio',
    version='0.0.3',
    setup_requires=[
        'setuptools>=45.0',
        'Cython',
    ],
    ext_modules = cythonize('libsgio.pyx')
)
