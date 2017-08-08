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
        'ida-netnode'
    ],

    packages = find_packages(),

    # Declare you ida plugins here
    ida_plugins = ['idarop_plugin_t.py'],

    package_data = {
        # copy any ida python plugin here
        # for pypi sdist
        '': ['idarop_plugin_t.py'],
    },
    include_package_data = True,
    
    # monkey patch install script for IDA plugin custom install
    cmdclass={'ida_install': IdaPluginInstallCommand}   
)