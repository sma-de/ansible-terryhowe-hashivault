#!/usr/bin/env python
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_argspec
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_auth_client
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_init
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

# TODO: add support for extra other supported params, see:
##  https://developer.hashicorp.com/vault/api-docs/auth/cert#create-ca-certificate-role
ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_auth_cert
version_added: "3.17.7 <-- TODO"
short_description: Hashicorp Vault cert based auth certs management module
description:
    - Module to manage certificates for cert based authentication method in Hashicorp Vault.
options:
    mount_point:
        description:
            - location where this auth_method is mounted. also known as "path"
        default: auth/cert
    certificate:
        description:
          - Certificate (public key) to register as auth master for this auth endpoint.
    name:
        description:
          - How this cert auth endpoint should be named inside Vault.
    display_name:
        description:
          - Display name for this cert endpoint.
        default: I(name)
    policies:
        description:
          - List of vault policies attached to this auth endpoint.
    ttl:
        description:
          - Maximal time to live for auth returned token, defaults to "0" aka unlimited.
        default: 0
    state:
        description:
          - If this cert role should be present or absent after configuration.
        default: present
extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
  - hashivault_auth_cert:
      name: web
      policies:
        - web
        - prod
      certificate: "{{ pem_cert }}"
'''


def main():
    argspec = hashivault_argspec()
    argspec['name'] = dict(required=True, type='str')
    argspec['policies'] = dict(required=True, type='list', elements='str')
    argspec['certificate'] = dict(required=True, type='str')
    argspec['mount_point'] = dict(required=False, type='str', default='auth/cert')
    argspec['display_name'] = dict(required=False, type='str', default=None)
    argspec['ttl'] = dict(required=False, type='int', default=0)
    argspec['state'] = dict(required=True, type='str', choices=['present', 'absent'])

    module = hashivault_init(argspec, supports_check_mode=True)
    result = hashivault_auth_cert(module)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_auth_cert(module):
    params = module.params
    client = hashivault_auth_client(params)
    changed = False
    desired_state = dict()

    result = {'changed': changed}

    role_name = params.get('name')
    state = params.get('state')

    desired_state['certificate'] = params.get('certificate')
    desired_state['policies'] = sorted(params.get('policies'))
    desired_state['mount_point'] = params.get('mount_point')
    desired_state['display_name'] = params.get('display_name') or role_name
    desired_state['ttl'] = params.get('ttl')

    # check current config
    current_state = dict()
    role_exists = True

    try:
        result = client.auth.cert.read_ca_certificate_role(
            role_name, mount_point=desired_state['mount_point']
        )['data']

        assert False, "da res => {}".format(result)
        current_state['policies'] = sorted(result['policies'].split(','))
        current_state['certificate'] = result['certificate']
        current_state['display_name'] = result['display_name']
        current_state['ttl'] = result['ttl']
    except InvalidPath:
        role_exists = False

    assert False, "{}, {}, breaker => {}".format(role_name, state, str(desired_state))

    if state == 'absent':
        ## handle absent state
        if not role_exists:
            # trying to absent a non existing role => noop
            return result

        client.auth.cert.delete_certificate_role(role_name,
          mount_point=desired_state['mount_point']
        )

        # existing role should be absented => delete it
        result['changed'] = True
        return result

    ## handle present state

    # check if current config matches desired config values, if they match, set changed to false to prevent action
    for k, v in current_state.items():
        if v != desired_state[k]:
            changed = True

    # if configs dont match and checkmode is off, complete the change
    if changed and not module.check_mode:
        desired_state['token_ttl'] = desired_state.pop('ttl')
        desired_state['token_policies'] = desired_state.pop('policies')

        client.auth.cert.create_ca_certificate_role(name,
           desired_state.pop('certificate'), **desired_state
        )

    return {'changed': changed}


if __name__ == '__main__':
    main()
