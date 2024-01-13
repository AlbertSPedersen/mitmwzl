from datetime import datetime
from httpx import AsyncClient
from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from ._constants import SOURCE_MAPPING_URL_PATTERN, SKIP_URL_PATTERN
from ._utils import get_response_content_type, get_burp_mimetype, to_burp_header_list
import asyncio
import json
import logging


class JSWZL:
	def __init__(self, api_url: str = 'http://localhost:37232', max_response_size: int = 104857600):
		"""
		:param api_url: URL of the jswzl API server (default: http://localhost:37232)
		:param max_response_size: Don't process responses with a body larger than this (default: 100 MiB)
		"""
		self._jswzl_api_client = AsyncClient(base_url=api_url, timeout=60)
		self.max_response_size = max_response_size
		self._processed_urls = set()

	"""
	Other addons might be rewriting URL or headers. We need to
	preserve the original values so they can be sent to jswzl.
	"""
	async def requestheaders(self, flow: HTTPFlow):
		if SKIP_URL_PATTERN.match(flow.request.path):
			flow.metadata['jswzl_skip'] = True
			return

		flow._original_request = flow.request.copy()

	async def request(self, flow: HTTPFlow):
		if flow.metadata.get('jswzl_skip') is True:
			return

		flow._original_request.raw_content = flow.request.raw_content

	async def response(self, flow: HTTPFlow):
		if flow.metadata.get('jswzl_skip') is True:
			return

		if hasattr(flow, '_jswzl_sourcemap_future'):
			flow._jswzl_sourcemap_future.set_result(flow.response)

		# Create background task to avoid blocking the response
		asyncio.create_task(self.send_to_jswzl(flow))

	async def error(self, flow: HTTPFlow):
		if hasattr(flow, '_jswzl_sourcemap_future'):
			flow._jswzl_sourcemap_future.set_exception(flow.error)

	async def send_to_jswzl(self, flow: HTTPFlow):
		# Let's not recurse
		if 'jswzl_sourcemap_subrequest' in flow.metadata:
			return

		# Ignore responses that have an empty body or are too large
		if not flow.response.content or len(flow.response.content) > self.max_response_size:
			return

		# Probably not fetching assets
		if flow._original_request.method != 'GET':
			return

		# TODO: Figure out how Burp parses "response.statedMimeType()"
		mimetype = get_burp_mimetype(get_response_content_type(flow))

		# jswzl ignores mimetypes other than SCRIPT and HTML
		if mimetype not in ['SCRIPT', 'HTML']:
			return

		sourcemap = await self.fetch_source_map(flow) if mimetype == 'SCRIPT' else None

		data = {
			'request': {
				'method': flow._original_request.method,
				'url': flow._original_request.url,
				# API does not parse the source map if host header is missing, and
				# there is no host header in HTTP/2 and HTTP/3
				'headers': to_burp_header_list(flow._original_request.headers) + [f'host: {flow._original_request.host_header}']
			},
			'response': {
				'status': flow.response.status_code,
				'body': flow.response.text,
				'headers': to_burp_header_list(flow.response.headers),
				'mimetype': mimetype
			},
			'timestamp': datetime.utcnow().isoformat(),
			'sourcemap': sourcemap,
			'scope': {
				# TODO: Implement URL filtering?
				'urlInScope': True,
				'refererInScope': True
			}
		}

		resp = await self._jswzl_api_client.post('/burp', json=data)

		chunk_files = resp.json()

		await self.fetch_js_chunks(flow, chunk_files)

		# The original request is no longer needed
		del flow._original_request

	async def fetch_js_chunks(self, flow: HTTPFlow, chunk_files: list[str]):
		for chunk in chunk_files:
			chunk_flow = flow.copy()

			chunk_flow.request = flow._original_request.copy()

			# I'm not sure why jswzl sometimes produces incorrect relative
			# paths like "static/chunks/517.78c3745e2c1177e4.js", when the
			# correct relative path is just the last component
			# TODO: Figure out if it's my addon or jswzl doing funny business
			chunk_flow.request.path_components = [*chunk_flow.request.path_components[:-1], chunk.split('/')[-1]]

			# Ignore already fetched chunks, if jswzl requests them again
			if chunk_flow.request.url in self._processed_urls:
				ctx.log(f'Ignoring already fetched chunk: {chunk_flow.request.url}', 'WARN')
				continue

			self._processed_urls.add(chunk_flow.request.url)

			# Make it show up in the request log
			if 'view' in ctx.master.addons:
				ctx.master.commands.call('view.flows.duplicate', [chunk_flow])

			ctx.master.commands.call('replay.client', [chunk_flow])

	async def fetch_source_map(self, flow: HTTPFlow):
		sourcemap_flow = flow.copy()

		sourcemap_flow.request = flow._original_request.copy()

		sourcemap_flow.metadata['jswzl_sourcemap_subrequest'] = True

		# Get sourcemap path from the JS file itself, if possible
		if match := SOURCE_MAPPING_URL_PATTERN.search(flow.response.text):
			source_mapping_url = match.group(1)
		else:
			# I guess if a JS file is located at "/" we will miss
			# out on this one ¯\_(ツ)_/¯
			if len(sourcemap_flow.request.path_components) == 0:
				return
			source_mapping_url = sourcemap_flow.request.path_components[-1] + '.map'

		sourcemap_flow.request.path_components = (
			*flow.request.path_components[:-1],
			source_mapping_url
		)

		# Don't fetch the same sourcemap twice
		if sourcemap_flow.request.url in self._processed_urls:
			ctx.log(f'Ignoring already fetched sourcemap: {sourcemap_flow.request.url}', 'WARN')
			return

		self._processed_urls.add(sourcemap_flow.request.url)

		loop = asyncio.get_event_loop()
		future = loop.create_future()

		# Can't use flow.metadata because mitmproxy attempts to pickle
		# but futures cannot be pickled
		sourcemap_flow._jswzl_sourcemap_future = future

		# For the UI to display the request
		if 'view' in ctx.master.addons:
			ctx.master.commands.call('view.flows.duplicate', [sourcemap_flow])

		ctx.master.commands.call('replay.client', [sourcemap_flow])

		try:
			# Timeout of 10 second
			response = await asyncio.wait_for(future, 10)
		except:
			sourcemap_flow.kill()

		if response.status_code == 200:
			try:
				# Sourcemaps are valid JSON objects. If this fails,
				# the response is not a valid sourcemap. This can
				# happen if the website is an SPA
				json.loads(response.text)
				return response.text
			except:
				pass
