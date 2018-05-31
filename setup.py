import os
from io import open
from setuptools import setup, find_packages

from __ida_setup__ import IdaPluginInstallCommand
from idarop import IDAROP_VERSION, IDAROP_DESCRIPTION


# read the contents of README file
package_directory = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(package_directory, 'README.md')
with open(readme_path, "r", encoding = 'utf-8') as f:
    long_description = f.read()


setup(
    name = 'idarop',
    version = IDAROP_VERSION,
    description = IDAROP_DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author = "lucasg",
    author_email = "lucas.georges@outlook.com",
    url = "https://github.com/lucasg/idarop",
    
    install_requires = [
    ],

    packages = find_packages(),
    py_modules = ['__ida_setup__', 'plugins/idarop_plugin_t'],

    # Declare your ida plugins here
    package_data = {
        'ida_plugins': ['plugins/idarop_plugin_t.py'],
    },
    
    # monkey patch install script for IDA plugin custom install
    cmdclass={'install': IdaPluginInstallCommand}   
)