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

import json
import shutil
from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.callback import CallbackBase
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.playbook.play import Play
import ansible.constants as C
from ansible.executor.task_queue_manager import TaskQueueManager


CLOUDIFY_MANAGER_PRIVATE_KEY_PATH = 'CLOUDIFY_MANAGER_PRIVATE_KEY_PATH'


class ResultCallback(CallbackBase):
    """A sample callback plugin used for performing an action as results come in

    If you want to collect all results into a single object for processing at
    the end of the execution, look into utilizing the ``json`` callback plugin
    or writing your own custom callback plugin
    """
    def v2_runner_on_ok(self, result, **kwargs):
        """Print a json representation of the result

        This method could store the result in an instance attribute for retrieval later
        """
        host = result._host
        ctx.logger.info(json.dumps({host.name: result._result}, indent=4))
        # print(json.dumps({host.name: result._result}, indent=4))

    def v2_playbook_on_task_start(self, task, is_conditional):
        ctx.logger.info('task has started')

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

def myexecute(command):
    try:
        run = Popen(command, stdout=PIPE, shell=True)
        for line in iter(run.stdout.readline, ""):
            yield line[:-1]
        run.stdout.close()
        # eturn_code = popen.wait()
        # if return_code:
        #     raise subprocess.CalledProcessError(return_code, cmd)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            'Unable to run command. Error {}'.format(str(e)))

def run_ansible_command(command):
    # since API is constructed for CLI it expects certain options to always be set, named tuple 'fakes' the args parsing options object
    Options = namedtuple(
        'Options',
        ['connection', 'module_path', 'forks',
            'become', 'become_method', 'become_user', 'check', 'diff'
        ])

    options = Options(
        connection='local',
        module_path=['/to/mymodules'],
        forks=10,
        become=None, become_method=None, become_user=None,
        check=False, diff=False
    )

    # initialize needed objects
    loader = DataLoader() # Takes care of finding and reading yaml, json and ini files
    passwords = dict(vault_pass='secret')

    # Instantiate our ResultCallback for handling results as they come in. Ansible expects this to be one of its main display outlets
    results_callback = ResultCallback()

    # create inventory, use path to host config file as source or hosts in a comma separated string
    inventory = InventoryManager(loader=loader, sources='localhost,')

    # variable manager takes care of merging all the different sources to give you a unifed view of variables available in each context
    variable_manager = VariableManager(loader=loader, inventory=inventory)

    # create datastructure that represents our play, including tasks, this is basically what our YAML loader does internally.
    play_source =  dict(
        name = "Ansible Play",
        hosts = 'localhost',
        gather_facts = 'no',
        tasks = [
            dict(action=dict(module='shell', args='ls'), register='shell_out'),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='pause', args=dict(minutes=1))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
            dict(action=dict(module='debug', args=dict(msg='{{shell_out.stdout}}'))),
         ]
    )

    # Create play object, playbook objects use .load instead of init or new methods,
    # this will also automatically create the task objects from the info provided in play_source
    play = Play().load(play_source, variable_manager=variable_manager, loader=loader)


    # Run it - instantiate task queue manager, which takes care of forking and setting up all objects to iterate over host list and tasks
    tqm = None
    try:
        tqm = TaskQueueManager(
                  inventory=inventory,
                  variable_manager=variable_manager,
                  loader=loader,
                  options=options,
                  passwords=passwords,
                  stdout_callback=results_callback,  # Use our custom callback instead of the ``default`` callback plugin, which prints to stdout
              )
        result = tqm.run(play) # most interesting data for a play is actually sent to the callback's methods
    finally:
        # we always need to cleanup child procs and the structres we use to communicate with them
        if tqm is not None:
            tqm.cleanup()

        # Remove ansible tmpdir
        shutil.rmtree(C.DEFAULT_LOCAL_TMP, True)

def run_command(command):
    for path in myexecute(command):
        ctx.logger.info(path)

    # try:
    #     output = run.communicate()
    # except Exception as e:
    #     raise exceptions.NonRecoverableError(
    #         'Unable to run command. Error {}'.format(str(e)))
    #
    # if run.returncode != 0:
    #     raise exceptions.NonRecoverableError(
    #         'Non-zero returncode. Output {}.'.format(output))

    # return output
    return None
