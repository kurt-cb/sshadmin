import os

bind = '0.0.0.0:5000'
workers = 1
threads = 4
preload_app = True
accesslog = '-'
errorlog = '-'


def post_fork(server, worker):
    import sshadmin
    sshadmin._start_ssh_auth_server_if_enabled()
