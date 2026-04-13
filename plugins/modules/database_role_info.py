# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_role_info
short_description: Read HashiCorp Vault database dynamic role configuration
version_added: 1.2.0
author: Matthew Johnson (@mjohns91)
description:
  - Read the configuration of dynamic roles in HashiCorp Vault Database Secrets Engine.
  - This module is read-only and does not modify role configuration.
options:
  mount_path:
    description: Database secrets engine mount point.
    default: database
    type: str
  role_name:
    description: Name of the dynamic role to read.
    required: true
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Read a dynamic role configuration with token authentication
  hashicorp.vault.database_role_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    role_name: readonly

- name: Read a dynamic role configuration with AppRole authentication
  hashicorp.vault.database_role_info:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    role_name: readwrite
  register: role_config

- name: Display role configuration
  ansible.builtin.debug:
    var: role_config.role
"""

RETURN = """
role:
  description: The dynamic role configuration data when the role exists.
  returned: when the role exists
  type: dict
  sample:
    db_name: "my-postgres-db"
    creation_statements:
      - "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
      - "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
    default_ttl: 3600
    max_ttl: 86400
    revocation_statements:
      - "DROP ROLE IF EXISTS '{{name}}';"
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC

try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
        get_authenticated_client,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import VaultDatabaseDynamicRoles
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
        VaultSecretNotFoundError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            # Role parameters
            mount_path=dict(type='str', default='database'),
            role_name=dict(type='str', required=True),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    mount_path = module.params['mount_path']
    role_name = module.params['role_name']

    try:
        db_roles = VaultDatabaseDynamicRoles(client, mount_path)
        result = db_roles.read_dynamic_role(role_name)
        module.exit_json(role=result)

    except VaultSecretNotFoundError:
        module.exit_json(role={})
    except VaultPermissionError as e:
        module.fail_json(msg=f'Permission denied: {e}')
    except VaultApiError as e:
        module.fail_json(msg=f'Vault API error: {e}')
    except Exception as e:
        module.fail_json(msg=f'Operation failed: {e}')


if __name__ == '__main__':
    main()
