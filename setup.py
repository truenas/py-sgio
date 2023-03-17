from setuptools import setup
from Cython.Build import cythonize
from Cython.Distutils.extension import Extension


setup(
    name='libsgio',
    version='0.0.4',
    setup_requires=[
        'setuptools>=45.0',
        'Cython',
    ],
    ext_modules = [
        Extension(
            'libsgio',
            cythonize('src/libsgio.pyx'),
        ),
        Extension(
            'libsgio.disk',
            cythonzie('src/disk.pyx'),
        )
)
