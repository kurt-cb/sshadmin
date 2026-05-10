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


Improvements made
-----------------

-------- Begin Already done -------
expand sshadmin_add to to a more generic "sshadmin.sh add user@machine" and support "sshadmin update" that check current certificate in .ssh and updates it if needed.  Also should support updatehost that will check the host cert expire and update it (requires sudo or root access).  Also on registerd users and hosts pages, show current cert (if any) and expire date (in hours, days and years from now).  Add a batch renew button and checkbox (include check all) that user can renew.  When pressed, it will take them to a page that allows them to cut/pased or download a script that user can run on one machine, that will ssh to other systems and update their keys.

on registration, if not root, and no ssh or su,  allow user to perform the host sign another way (possibly a separate session) and paste in the host key and proof of ownership (signed registration hash). explain how to do it for the host type (windows or linux).
Provide a power shell version of the restistration script for windows.
The registration window with all it's options is too busy.  put a tab to group options by use case (linux shell, powershell, teraterm, etc.).  Include the host type (linux/windows/etc) in the user_credential or host table.



new big idea: automatically issue user certificates that are extreamly short lived (hour or less) to users that have been pre-auhorized to a host machine by another sshadmin user.  Allow user to run a bash script that wraps ssh and retrieves the user certificate for the host, and updates .ssh/config with the retrieved key for that host.  The script will ssh to the ssh_auth_server to retrieve the user certificate based on user name

1) Create a new page that allows user to pre-authorize key signing for a host owned or co-owned by that user.
User must have verified access to the host private key during registration.  If not verified, allow user to verify using same process during registration.  The new page will allow the same selections as the admin page,
but restrict the login host to those owned by the user, and store the pre-authorization in the database.
Page will show a list of authorizations and allow edit/delete.
2) In order to use the pre-authorization, add an ssh command to the ssh server that signs a pre-authorized user key, and also a web page.  This allows a user to retrieve a user certificate for a pre-authorized machine by using 'ssh {sshadmin user}@sshadmin get-key {server}'. this will authenticate the user with their registered ssh key, then sign the user key with permisions set by the pre-authorization.  This allows user to grant access to any registered user for machines they own.  Add another page that shows a sample script that uses ssh to retrieve the user certificate and add it to the openssh user config file for that host.
3) Create web page and rest api that will issue certificate, create a oneliner script that will integrate cert into client and explain how to modify .ssh/config to use issued certificate for the host.
-------- End already done

Add Linux (alpine/busybox) help that uses ash instead of bash for examples

http://localhost:5000/credentials/add should follow a similar flow to regitsriation, except sshadmin user is fixed to the account that is adding.  Including help, oneliner etc.

Registration one liner curl is not clear as to what user name you will have in sshadmin, or what user_name@machine should be specified.  I think that would be more clear using $USER and $(hostname) if that is what is needed

Error box on top in all dialogs is not very noticable. use popup or expand it to take more of the screen, same for all screens.  Red is not an international color for error.

Dashboard is more of an administration thing at this point.  probably should not be visible for non-admins and should have a list of the adminstrator's machines. for normal users, just show user related hosts and SSH keys on them in a list in a tree form.

Issuing user certs should not allow users access to other accounts.  Therefore it should not be possible for a non-machine owner to issue a user certificate.  I think this means that machine owner should be able to see all users registered to on the system.  machine owner authorizes a key for an user to be signed, and can restrict to just the username, or a list of users that the key works for. I think this means the host table needs to be expanded with the certificate information so the user can not specify anything.  Just request re-sign, and the issue fields are pre-filled and not editable.

The security model for the linux system must be maintained by the machine owner, only.  Verify there is no way for a user to create a certificate that authorizes access to any account not configured by the owner.

Add unit tests for all apis not covered and verify security model.

When registering with "curl -fsSL "http://localhost:5000/download/sshadmin_add" -o sshadmin_add && chmod +x sshadmin_add
./sshadmin_add youruser@this-host" user needs probably needs to supply their password for sudo.  Instead, inform the user that they are not root, and continuing will not register the host.  If the host is already registered, then sudo is not required, so script could check that first.  If the user aborts, inform them to run "sudo ./sshadmin_add".  Add unit test that verifies this flow.