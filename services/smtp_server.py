import smtpd
import asyncore

class SimpleSMTP(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print(f'Mail from {mailfrom} to {rcpttos}. Data:\n{data}\n')

server = SimpleSMTP(('0.0.0.0', 25), None)
print('SMTP server running on port 25')
asyncore.loop()