import re


SOURCE_MAPPING_URL_PATTERN = re.compile(r'^//.*sourceMappingURL=(.*)$', re.MULTILINE)

# Specified URL path patterns to skip sending to jswzl/fetching sourcemaps
# - /cdn-cgi/ is Cloudflare's reserved path prefix, used for e.g. JavaScript Challenges
SKIP_URL_PATTERN = re.compile(r'^/cdn-cgi/')
