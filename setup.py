from setuptools import setup, Extension
from Cython.Build import cythonize

sgio = [
    Extension("libsgio", ["libsgio.pyx"],
              libraries=["sgutils2"],
              library_dirs=["/usr/lib"],
              include_dirs=["/usr/include"])
]

setup(
    name='libsgio',
    version='0.1.0',
    setup_requires=[
        'setuptools>=45.0',
        'Cython',
    ],
    ext_modules = cythonize(sgio)
)
