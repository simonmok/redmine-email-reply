from redminelib import Redmine
from redminelib.exceptions import AuthError, ForbiddenError, ResourceNotFoundError
from io import BytesIO

import base64
import binascii
import datetime
import email
import email.header
import imaplib
import re
import sys
import time

IMAP_SERVER = ''
EMAIL_ACCOUNT = ''
EMAIL_PASSWORD = ''
EMAIL_FOLDER = 'INBOX'
EMAIL_FILTER = '(ON {0})'.format(time.strftime("%d-%b-%Y"))
EMAIL_EXCEPTION = ''

REDMINE_HOST = ''
REDMINE_USER = ''
REDMINE_PASSWORD = ''

TITLE_REGEX = re.compile('.*\[.+ - .+ #\d+\].+')
BASE64_REGEX = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')

def process_mailbox(mailbox):

	redmine = Redmine(REDMINE_HOST, username=REDMINE_USER, password=REDMINE_PASSWORD)

	try:
		rv, data = mailbox.login(EMAIL_ACCOUNT, EMAIL_PASSWORD) 
		print('[%s] Login completed with return data "%s"' % (rv, data[0].decode('utf-8')))
	except imaplib.IMAP4.error:
		print('Login to %s failed' % EMAIL_ACCOUNT)
		sys.exit(1)

	rv, data = mailbox.select(EMAIL_FOLDER)
	if rv != 'OK':
		print('Mail box %s not found' % EMAIL_FOLDER)
		sys.exit(1)

	print('[%s] Mailbox %s selected with %s mail(s)' % (rv, EMAIL_FOLDER, data[0].decode('utf-8')))
	rv, data = mailbox.search(None, EMAIL_FILTER) 

	mails = data[0].split()
	print('[%s] Processing %d mail(s)' % (rv, len(mails)))
	process_count = 0

	for mail in mails:

		rv, data = mailbox.fetch(mail, '(RFC822)')
		if rv != 'OK':
			print('Error getting message', mail)
			continue

		msg = email.message_from_bytes(data[0][1])
		email_header = email.header.make_header(email.header.decode_header(msg['Subject']))
		subject = str(email_header)

		if (TITLE_REGEX.match(subject) is not None):
		
			print('=' * 30)
			project_id, journal_id = parse_title(subject)
			if (journal_id == 0):
				print('Ticket ID not determined from subject "%s"' % subject)
				continue

			print('Issue ID:', journal_id)
			print('Project ID:', project_id)
			print('Date:', msg['Date'])
			print('To:', msg['To'] if 'To' in msg else '(None)')
			print('From:', msg['From'])

			try:
				redmine_project = redmine.issue.get(journal_id).project
				if (redmine_project.name != project_id):
					print('Project "%s" does not match. Expecting "%s".' % (project_id, redmine_project.name))
					continue
			except ResourceNotFoundError:
				print('Resource not found error (id: %d) during Redmine API call' % journal_id)
				continue
			except AuthError:
				print('Authentication error during Redmine API call')
				continue

			sender = parse_email(msg['From'].lower())
			if (EMAIL_EXCEPTION == sender):
				print('Redmine sender found. Email skipped')
				continue

			users = [redmine.user.get(membership.user.id).login.lower() for membership in redmine_project.memberships]
			if (not sender in users):
				print('Sender %s is not allowed to post in ticket' % sender)
				continue
			else:
				print('Sender %s is found from %d membership(s) of ticket' % (sender, len(users)))

			notes = get_body(msg)
			print('Body:', notes)

			attachments = get_attachment(msg)
			print('Attachments:', list(attachments.keys()) if attachments else '(None)')

			uploads = [{'filename': k, 'path': BytesIO(v)} for (k, v) in attachments.items()]
			try:
				if (uploads):
					print('Sending ticket update (ID %d) with %d attachment(s) to Redmine' % (journal_id, len(attachments)))
					print('Ticket post successfully' if redmine.issue.update(journal_id, notes=notes, uploads=uploads) else 'Error in ticket post')
				else:
					print('Sending ticket update (ID %d) to Redmine' % journal_id)
					print('Ticket post successfully' if redmine.issue.update(journal_id, notes=notes) else 'Error in ticket post')
			except ForbiddenError:
				print('Forbidden error in sending ticket update (ID %d)' % journal_id)
				
			process_count += 1
			mailbox.store(mail, '+FLAGS', '\\Deleted')

	print('=' * 30)
	if process_count > 0:
		print('Purging fetched mail messages')
		print('Result: %s' % mailbox.expunge()[0])

	mailbox.close()
	print('Logging out from %s' % EMAIL_ACCOUNT)
	print('Summary: %d mail(s) processed successfully' % process_count)
	mailbox.logout()


def parse_email(value):
	index_start = value.find('<')
	index_end = value.find('>')
	if (index_start < 0 or index_end < 0 or index_start > index_end):
		return value
	return value[index_start + 1 : index_end]


def parse_title(value):
	tag = value[value.find('[') + 1 : value.find(']')]
	values = tag.split('#')
	project = values[0].split(' - ')
	journal_id = int(values[-1]) if len(values) > 1 else 0
	return project[0], journal_id


def base64_decode(value):
	if BASE64_REGEX.match(value) is None:
		return value
	try:
		decoded = base64.b64decode(value)
	except binascii.Error:
		return value
	try:
		return decoded.decode('ascii')
	except UnicodeDecodeError:
		return str(decoded)


def get_body(msg):
	bodies = set()
	if msg.is_multipart():
		for payload in msg.get_payload():
			if isinstance(payload.get_payload(), str):
				if payload.get_filename() is None:
					bodies.add(base64_decode(payload.get_payload()))
			else:
				for item in payload.get_payload():
					if isinstance(item, email.message.Message) and item.get_filename() is None:
						bodies.add(base64_decode(item.get_payload()))
	else:
		if msg.get_filename() is None:
			bodies.add(base64_decode(msg.get_payload()))

	body = list(bodies)[0] if len(bodies) == 1 else min(bodies, key=len)
	return body.strip()


def get_attachment(msg):
	if not msg.is_multipart():
		return dict()
	return dict((part.get_filename(), part.get_payload(decode=True)) for part in msg.walk() if part.get_filename() is not None)


if __name__ == '__main__':
	print('Program started at %s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
	mailbox = imaplib.IMAP4_SSL(IMAP_SERVER)
	process_mailbox(mailbox)
	print('Program completed at %s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))