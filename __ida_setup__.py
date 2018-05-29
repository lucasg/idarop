import os
import sys
import getpass
import distutils
from distutils.core import setup
from setuptools.command.install import install


if (sys.version_info > (3, 0)):
    raise ImportError("Idapython runs in a Python 2.7 interpreter, please execute this install setup with it.")

def ida_install_dir_windows(version, *args):
    IDA_INSTALL_DIR_WINDOWS = {
        '6.8' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.8", "plugins"),
        '6.9' : os.path.join(os.environ.get("ProgramFiles(x86)", "KeyError"), "IDA 6.9", "plugins"),
        '7.0' : os.path.join(os.environ.get("ProgramW6432", "KeyError"), "IDA 7.0", "plugins"),
    }

    return IDA_INSTALL_DIR_WINDOWS[version]

def ida_install_dir_macos(version, *args):
    IDA_INSTALL_DIR_MACOS = {
        '6.8' : os.path.join("/Applications", "IDA Pro 6.8", "idaq.app/Contents/MacOS/plugins"),
        '6.9' : os.path.join("/Applications", "IDA Pro 6.9", "idaq.app/Contents/MacOS/plugins"),
        '7.0' : os.path.join("/Applications", "IDA Pro 7.0", "idaq.app/Contents/MacOS/plugins"),
    }

    return IDA_INSTALL_DIR_MACOS[version]

def ida_install_dir_linux(version, is_user, *args):
    IDA_INSTALL_DIR_LINUX_USER = {
        '6.8' : os.path.join("/home", getpass.getuser() ,"IDA 6.8", "plugins"),
        '6.9' : os.path.join("/home", getpass.getuser() ,"IDA 6.9", "plugins"),
        '7.0' : os.path.join("/home", getpass.getuser() ,"IDA 7.0", "plugins"),
    }

    IDA_INSTALL_DIR_LINUX_SYSTEM = {
        '6.8' : os.path.join("/opt", "IDA 6.8", "plugins"),
        '6.9' : os.path.join("/opt", "IDA 6.9", "plugins"),
        '7.0' : os.path.join("/opt", "IDA 7.0", "plugins"),
    }

    if is_user:
        return IDA_INSTALL_DIR_LINUX_USER[version]
    else:
        return IDA_INSTALL_DIR_LINUX_SYSTEM[version]

IDA_SUPPORTED_VERSIONS = ('6.8','6.9','7.0')

IDA_INSTALL_DIRS = {
    
    # On Windows, the folder is at C:\Program Files (x86)\IDA %d\plugins
    'win32' : ida_install_dir_windows,

    'cygwin': ida_install_dir_windows,

    # On MacOS, the folder is at /Applications/IDA\ Pro\ %d/idaq.app/Contents/MacOS/plugins
    'darwin' : ida_install_dir_macos,

    # On Linux, the folder may be at /opt/IDA/plugins/
    'linux2' : ida_install_dir_linux,

    # Python 3 
    'linux' : ida_install_dir_linux,
}       

class IdaPluginInstallCommand(install):
    description = "install the current plugin in IDA plugin folder."
    user_options = install.user_options + [
        ('ida', None, 'force custom ida install script.'),
        ('ida-version=', None, 'specify ida version.'),
        ('ida-install-deps', None, 'install ida plugin dependencies.'),
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.ida = False # explicitely tell setuptools to use the ida setup script
        self.ida_version = None # locate default ida version
        self.ida_install_deps = False # Install plugin deps

    def finalize_options(self):
        
        # Search for a supported version installed
        if self.ida_version == None:

            for ida_version in IDA_SUPPORTED_VERSIONS:
                ida_install_dir = IDA_INSTALL_DIRS[sys.platform](ida_version, self.user)

                if os.path.exists(ida_install_dir):
                    self.ida_version = ida_version
                    self.announce("[IDA PLUGIN INSTALL] No ida version provided, using default version : %s" % self.ida, level=distutils.log.ERROR)
                    break

            

        assert self.ida_version in IDA_SUPPORTED_VERSIONS, 'Supported IDA on this platform : %s' % IDA_SUPPORTED_VERSIONS
        install.finalize_options(self)

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
            
            if not self.dry_run:
                pip.main(['install', '-t', install_dir, "--ignore-installed" ,  dependency])

    def install_packages(self, dist, install_dir):
        # type:  (distutils.core.install, setuptools.dist.Distribution, str) -> void
        """ Install python packages """

        for package in dist.packages:
            self.announce("[IDA PLUGIN INSTALL] copy package %s -> %s" % (package, install_dir), level=distutils.log.INFO)

            if not self.dry_run:
                self.copy_tree(package, os.path.join(install_dir, package))

    def install_plugins(self, dist, install_dir):
        # type:  (distutils.core.install, setuptools.dist.Distribution, str) -> void
        """ Install ida plugins entry points """

        ida_plugins = dist.package_data.get('ida_plugins', [])
        for plugin in ida_plugins:
            self.announce("[IDA PLUGIN INSTALL] copy plugin %s -> %s" % (plugin, install_dir), level=distutils.log.INFO)

            if not self.dry_run:
                self.copy_file(plugin,install_dir)

    def run(self, *args, **kwargs):
        """ Install ida plugins routine """
                
        dist = self.distribution  # type: setuptools.dist.Distribution

        # Custom install script
        if self.ida:
            install_dir = self.root # respect user-override install dir
            if not install_dir:     # otherwise return the ida install dir
                install_dir = IDA_INSTALL_DIRS[sys.platform](self.ida_version)
        
            if self.ida_install_deps:
                self.install_dependencies(dist, install_dir)

            self.install_packages(dist, install_dir)
            self.install_plugins(dist, install_dir)

        install.run(self)