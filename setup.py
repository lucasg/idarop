from setuptools import setup, find_packages
from __ida_setup__ import IdaPluginInstallCommand
from idarop import IDAROP_VERSION, IDAROP_DESCRIPTION



setup(
    name = 'idarop',
    version = IDAROP_VERSION,
    description = IDAROP_DESCRIPTION,
    long_description = IDAROP_DESCRIPTION,
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