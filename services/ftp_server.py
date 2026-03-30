from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_anonymous('/tmp', perm='elr')
authorizer.add_user('user', 'password', '/tmp', perm='elradfmwMT')

handler = FTPHandler
handler.authorizer = authorizer

server = FTPServer(("0.0.0.0", 21), handler)
print('FTP server running on port 21')
server.serve_forever()