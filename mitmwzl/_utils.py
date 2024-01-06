from email.message import Message
from mitmproxy.http import HTTPFlow, Headers
from mimetypes import guess_type


def get_burp_mimetype(content_type: str):
	if content_type in ['application/javascript', 'text/javascript']:
		return 'SCRIPT'
	elif content_type in ['text/html']:
		return 'HTML'
	elif content_type in ['application/json']:
		return 'JSON'
	return 'UNRECOGNIZED'

def get_response_content_type(flow: HTTPFlow):
	if 'content-type' in flow.response.headers and (c := parse_content_type(flow.response.headers.get('content-type'))):
		return c.lower()
	elif c := guess_type(flow.request.url)[0]:
		return c.lower()
	return 'unknown'

def parse_content_type(content_type: str) -> str:
	email = Message()
	email['content-type'] = content_type
	return email.get_params()[0][0]

def to_burp_header_list(headers: Headers):
	return [f'{k}: {v}' for k, v in headers.items()]
