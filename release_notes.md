Version 0.0.9
-------------
What was built:

Foundation (sshadmin.py)

CAGroup, HostGroupMembership, UserGroupMembership models with full relationships
User and Host updated with group_memberships relationships
SSHCertificateGenerator.generate_user_certificate() accepts ca_key_override so each group signs with its own CA
_do_issue_user_cert() routes through _get_user_cert_ca_key() — in simple mode uses the main CA (unchanged), in multi-group mode uses the user's group CA
_ensure_default_group() called at startup — idempotent, migrates all existing users/hosts into the default group
_ssh_add_machine() now enrols new users and hosts in the default group automatically
_pending_group_request_count() injected into every template as pending_group_requests
multi_group_enabled also injected globally
Routes

/groups — list all groups with membership status
/groups/create — creates group + generates its own CA keypair
/groups/<id> — detail view: pending approvals, members, hosts, add/remove
/groups/<id>/request-access, /approve-user, /reject-user, /remove-user, /add-host, /remove-host
/help, /help/key-concepts, /help/security-model, /help/groups — all public
Templates

groups.html, group_create.html, group_detail.html
help/index.html, help/key_concepts.html, help/security_model.html, help/groups.html
UI changes

Help dropdown in navbar (always visible, even before login)
Groups nav link with pending-request badge (only shown when multi-group enabled)
Admin Settings — new "CA Group Mode" card with enable/disable toggle
Registration page — "What Happens After Registration?" section that adapts to simple vs. multi-group mode
Simple mode remains completely unchanged in behaviour — the default group is invisible infrastructure.
