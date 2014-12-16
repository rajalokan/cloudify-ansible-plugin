########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License,  Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#                http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,  software
# distributed under the License is distributed on an 'AS IS' BASIS,
#   * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,  either express or implied.
#   * See the License for the specific language governing permissions and
#   * limitations under the License.

# for running shell commands
import subprocess
# for finding out the linux distro
import os
import platform
# for downloading rpm/ppc files
import urllib

# ctx is imported and used in operations
from cloudify import ctx
# put the operation decorator on any function that is a task
from cloudify.decorators import operation
# Import Cloudify exception
from cloudify.exceptions import NonRecoverableError


def _run_shell_command(command):
    """Runs any shell command
    """

    ctx.logger.info('Running shell command: {0}'.format(command))
    try:
        run = subprocess.check_call(
            command)
    except subprocess.CalledProcessError:
        ctx.logger.error('Unable to run shell command: {0}'.format(command))
        raise NonRecoverableError('Command failed: {0}'.format(command))
    return run


def _get_package_manager():
    """Returns the Package Manager for the distrobution
    """

    package_manager = 'apt-get'
    distro, version = _get_distro_version()
    if distro == 'Ubuntu':
        ctx.logger.info('{0} is the Linux distribution.'.format(distro))
        package_manager = 'apt-get'
    elif distro == 'Centos':
        ctx.logger.info('{0} is the Linux distribution.'.format(distro))
        package_manager = 'yum'
    else:
        ctx.logger.error(
            'Currently Operating System {0} is not supported'.format(distro))
        exit(1)
    return package_manager


def _install_package(package):
    """ Installs a Package
    """

    package_manager = _get_package_manager()
    ctx.logger.info('Installing {0}'.format(package))
    command = ['sudo', 'pip', '--version']
    code = _run_shell_command(command)
    if code == 0:
        _try_pip_install()
    else:
        _update_package_manager(package_manager)
        q, y = _install_args(package_manager)
        command = ['sudo', package_manager, 'install', package, q, y]
        _run_shell_command(command)
    _validate_installation(package)


def _install_args(package_manager):
    """ Returns Install Arguments for a Package Manager
    """

    if package_manager == 'apt-get':
        quiet_output = '-qq'
        assume_yes = '-y'
    if package_manager == 'yum':
        quiet_output = '-q'
        assume_yes = '-y'
    return quiet_output, assume_yes


def _get_distro_version():
    """ Gets the Distrobution
    """

    info = platform.dist()
    distro = info[0]
    version = info[1]
    return distro, version


def _add_repo(package_manager):
    """ Gets the Distrobution
    """

    ctx.logger.info('Installing Additional Repositories to {0}'.format(
        package_manager))
    if package_manager == 'yum':
        _install_epel_repo(package_manager)
    elif package_manager == 'apt-get':
        _install_ppa_repo(package_manager)
    else:
        ctx.logger.error('Not yum or apt-get.')


def _install_epel_repo(package_manager):
    """ Installs the EPEL Repo
    """

    wget_url = 'http://dl.fedoraproject.org/pub/epel/5/x86_64/'
    distro, version = _get_distro_version()
    if version == '5*':
        rpm_version = 'epel-release-5-4.noarch.rpm'
    elif version == '6*':
        rpm_version = 'epel-release-6-8.noarch.rpm'
    elif version == '7*':
        rpm_version = 'epel-release-7-1.noarch.rpm'
    else:
        rpm_version = ''
        ctx.logger.error('invalid version of CentOs: {0}'.format(version))
    filename = os.path.join('/tmp', rpm_version)
    if not os.path.exists(filename):
        ctx.logger.info('Deleting Existing RPM file: {0}'.format(filename))
        ctx.logger.info('Downloading EPEL RPM: {0}{1}'.format(
            wget_url, rpm_version))
        urllib.urlretrieve(wget_url + rpm_version, filename)
    command = ['sudo', 'rpm', '-Uvh', '/tmp/' + rpm_version]
    _run_shell_command(command)


def _install_dependency(package_manager):
    """Installs the Software Properties Common Dependency
    """

    command = ['sudo', 'apt-get', '-f', 'install', '-y']
    _run_shell_command(command)


def _install_ppa_repo(package_manager):
    """ Installs the PPA repos
    """

    q, y = _install_args(package_manager)
    command = ['sudo', 'apt-get', 'install',
               'software-properties-common', 'python-software-properties',
               q, y]
    _run_shell_command(command)
    _install_dependency(package_manager)
    command = ['sudo', 'apt-add-repository', 'ppa:ansible/ansible', '-y']
    _run_shell_command(command)


def _update_package_manager(package_manager):
    """ Updates a Package Manager
    """

    command = ['sudo', 'apt-get', 'clean']
    _run_shell_command(command)
    _add_repo(package_manager)
    ctx.logger.info('Updating {0}'.format(package_manager))
    command = ['sudo', package_manager, 'update']
    _run_shell_command(command)


def _try_pip_install():
    """ The vagrant boxes fail, so I am adding this here to use pip
        as a last resort
    """

    command = ['sudo', 'pip', 'install', 'ansible']
    _run_shell_command(command)


def _validate_installation(package):
    """ validate the installation
    """

    ctx.logger.info('Validating {0}: '.format(package))
    command = [package, '--version']
    code = _run_shell_command(command)

    if code > 0:
        ctx.logger.info('Installation was unsuccessful')
    else:
        ctx.logger.info('Installation was successful')


@operation
def install(**kwargs):
    """ Wraps _install_package
    """

    if 'package_name' in kwargs.iteritems():
        package = package_name
    else:
        package = 'ansible'
    _install_package(package)
