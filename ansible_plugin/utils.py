########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

# Built-in Imports
import os
import tempfile
from subprocess import Popen, PIPE

# Third-party Imports

# Cloudify imports
from cloudify import ctx
from cloudify import exceptions

CLOUDIFY_MANAGER_PRIVATE_KEY_PATH = 'CLOUDIFY_MANAGER_PRIVATE_KEY_PATH'


def get_playbook_path(playbook):

    try:
        path_to_file = ctx.download_resource(playbook)
    except exceptions.HttpException as e:
        raise exceptions.NonRecoverableError(
            'Could not get playbook file: {}.'.format(str(e)))

    return path_to_file


def get_inventory_path(inventory):

    if not inventory:
        inventory.append(ctx.instance.host_ip)

    _, path_to_file = tempfile.mkstemp()

    with open(path_to_file, 'w') as f:
        for host in inventory:
            f.write('{0}\n'.format(host))

    return path_to_file


def get_agent_user(user=None):

    if not user:
        if 'user' not in ctx.instance.runtime_properties:
            user = ctx.bootstrap_context.cloudify_agent.user
            ctx.instance.runtime_properties['user'] = user
        else:
            user = ctx.instance.runtime_properties['user']
    elif 'user' not in ctx.instance.runtime_properties:
        ctx.instance.runtime_properties['user'] = user

    return user


def get_keypair_path(key=None):

    if not key:
        if 'key' in ctx.instance.runtime_properties:
            key = ctx.instance.runtime_properties['key']
        elif CLOUDIFY_MANAGER_PRIVATE_KEY_PATH in os.environ:
            key = os.environ[CLOUDIFY_MANAGER_PRIVATE_KEY_PATH]
        else:
            key = ctx.bootstrap_context.cloudify_agent.agent_key_path

    if 'key' not in ctx.instance.runtime_properties:
        ctx.instance.runtime_properties['key'] = key

    key = os.path.expanduser(key)
    os.chmod(key, 0600)

    return key


def write_configuration_file(config):

    home = os.path.expanduser("~")

    file_path = os.path.join(home, '.ansible.cfg')

    with open(file_path, 'w') as f:
        f.write(config)

    return file_path


def run_command(command):

    try:
        run = Popen(command, stdout=PIPE)
        for line in iter(run.stdout.readline, ''):
            ctx.logger.info(line)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            'Unable to run command. Error {}'.format(str(e)))

    try:
        output = run.communicate()
    except Exception as e:
        raise exceptions.NonRecoverableError(
            'Unable to run command. Error {}'.format(str(e)))

    if run.returncode != 0:
        raise exceptions.NonRecoverableError(
            'Non-zero returncode. Output {}.'.format(output))

    return output
