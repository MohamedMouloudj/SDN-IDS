import time

from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A, QTYPE

class StaticResolver(BaseResolver):
    """Return a dummy A record for every query."""

    RECORDS = {
        'http.local.':  '192.168.10.10',
        'ftp.local.':   '192.168.20.10',
        'smtp.local.':  '192.168.20.11',
        'dns.local.':   '192.168.20.12',
    }

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        ip = self.RECORDS.get(qname, '192.168.10.10')
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
        return reply

server = DNSServer(StaticResolver(), port=53, address='0.0.0.0')
server.start_thread()
print('DNS server running on port 53')

while True:
    time.sleep(1)