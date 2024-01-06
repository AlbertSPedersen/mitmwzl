# mitmwzl

A mitmproxy addon for jswzl similar in functionality to the official Burp Suite extension. The addon sends JavaScript files and sourcemaps to jswzl for futher analysis.

**Important:** This project is not officially supported by jswzl and may break at any time. Please do not contact the jswzl author about issues with this addon.

## Links

* [jswzl](https://www.jswzl.io)
* [mitmproxy](https://mitmproxy.org)

## How to use

First, install mitmwzl from PyPI.

```
pip install mitmwzl
```

Then create a Python script named `jswzl.py` containing the following piece of code.

```py
from mitmwzl import JSWZL


addons = [
	JSWZL()
]
```

Finally, run mitmproxy with the script you just created.

```
mitmproxy -s jswzl.py
```

If you press `SHIFT + E` to open the mitmproxy event log, you should see a message stating the script was loaded.

```
info: [12:21:01.595] Loading script jswzl.py
info: [12:21:01.643] HTTP(S) proxy listening at *:8080.
```

Refer to the [mitmproxy documentation](https://docs.mitmproxy.org/stable/addons-overview/) for more information about addons.
