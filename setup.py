from setuptools import setup 
import setuptools

setup(
    name='stub_builder',
    author="Christopher R",
    author_email="https://github.com/ChrisTheCoolHut",
    version='0.1',
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    long_description="Create function calling stubs fast!",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts':
        [
            'stub_builder = stub_builder.stub_builder:main'
        ]
        },
    install_requires=[
        "r2pipe"
        ]
)
