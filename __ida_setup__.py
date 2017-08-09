import os
import sys
import distutils
from distutils.core import setup
from setuptools.command.install import install


IDA_INSTALL_DIRS = {
    
    # On Windows, the folder is at C:\Program Files (x86)\IDA %d\plugins
    'win32' : {
        '6.8' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.8", "plugins"),
        '6.9' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.9", "plugins"),
        '7.0' : os.path.join(os.environ.get("ProgramFiles", "KeyError"), "IDA 7.0", "plugins"),
    },

    'cygwin': {
        '6.8' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.8", "plugins"),
        '6.9' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.9", "plugins"),
        '7.0' : os.path.join(os.environ.get("ProgramFiles", "KeyError"), "IDA 7.0", "plugins"),
    },

    # On MacOS, the folder is at /Applications/IDA\ Pro\ %d/idaq.app/Contents/MacOS/plugins
    'darwin' : {
        '6.8' : os.path.join("/Applications", "IDA Pro 6.8", "idaq.app/Contents/MacOS/plugins"),
        '6.9' : os.path.join("/Applications", "IDA Pro 6.9", "idaq.app/Contents/MacOS/plugins"),
        '7.0' : os.path.join("/Applications", "IDA Pro 7.0", "idaq.app/Contents/MacOS/plugins"),
    },

    # On Linux, the folder may be at /opt/IDA/plugins/
    'linux2' : {
        '6.8' : os.path.join("/opt", "IDA", "plugins"),
        '6.9' : os.path.join("/opt", "IDA", "plugins"),
        '7.0' : os.path.join("/opt", "IDA", "plugins"),
    },

    'linux' : { # Python3 version
        '6.8' : os.path.join("/opt", "IDA", "plugins"),
        '6.9' : os.path.join("/opt", "IDA", "plugins"),
        '7.0' : os.path.join("/opt", "IDA", "plugins"), 
    }   
}       

class IdaPluginInstallCommand(install):
    description = "install the current plugin in IDA plugin folder."
    user_options = install.user_options + [
        ('ida=', None, 'specify ida version.'),
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.ida = None # locate default ida version

    def finalize_options(self):
        
        # Search for a supported version installed
        if self.ida == None:
            for ida_version in IDA_INSTALL_DIRS[sys.platform]:
                if os.path.exists(IDA_INSTALL_DIRS[sys.platform][ida_version]):
                    self.ida = ida_version
                    break

            print("[IDA PLUGIN INSTALL] No ida version provided, using default version : %s" % self.ida)

        assert self.ida in IDA_INSTALL_DIRS[sys.platform].keys(), 'Supported IDA on this platform : %s' % IDA_INSTALL_DIRS[sys.platform].keys()

    def install_dependencies(self, dist, install_dir):
        # type:  (distutils.core.install, setuptools.dist.Distribution, str) -> void
        """ Recursively install dependency using pip (for those on pipy) """

        if not len(dist.install_requires):
            return


        # inner import in order to prevent build breakage 
        # on old Python2 installs with no pip package unless 
        # there is actually a need for it.
        import pip

        for dependency in dist.install_requires:
            self.announce("[IDA PLUGIN INSTALL] installing dependency %s -> %s" % (dependency, install_dir), level=distutils.log.INFO)

            if not dist.dry_run:
                pip.main(['install', '-t', install_dir, "--ignore-installed" ,  dependency])

    def install_packages(self, dist, install_dir):
        # type:  (distutils.core.install, setuptools.dist.Distribution, str) -> void
        """ Install python packages """

        for package in dist.packages:
            self.announce("[IDA PLUGIN INSTALL] copy package %s -> %s" % (package, install_dir), level=distutils.log.INFO)

            if not dist.dry_run:
                self.copy_tree(package, os.path.join(install_dir, package))

    def install_plugins(self, dist, install_dir):
        # type:  (distutils.core.install, setuptools.dist.Distribution, str) -> void
        """ Install ida plugins entry points """

        ida_plugins = dist.package_data.get('ida_plugins', [])
        for plugin in ida_plugins:
            self.announce("[IDA PLUGIN INSTALL] copy plugin %s -> %s" % (plugin, install_dir), level=distutils.log.INFO)

            if not dist.dry_run:
                self.copy_file(plugin,install_dir)

    def run(self, *args, **kwargs):
        """ Install ida plugins routine """
                
        dist = self.distribution  # type: setuptools.dist.Distribution
        install_dir = IDA_INSTALL_DIRS[sys.platform][self.ida]

        
        self.install_dependencies(dist, install_dir)
        self.install_packages(dist, install_dir)
        self.install_plugins(dist, install_dir)