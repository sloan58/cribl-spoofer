import gzip
import json

from scapy.all import send, IP, UDP, Raw
from starlette.applications import Starlette
from starlette.config import Config
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        auth_header = request.headers.get('Authorization')
        if auth_header is None or auth_header != f'Bearer {API_TOKEN}':
            return JSONResponse('Unauthorized', status_code=401)
        response = await call_next(request)
        return response


class GunzipMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if "gzip" in request.headers.getlist("Content-Encoding"):
            data = await request.body()
            request._body = gzip.decompress(data)
        response = await call_next(request)
        return response


async def handle_event(event):
    original_host = event['host']
    destination = event['vip']
    source_type = event['sourcetype']
    dport = event['destinationPort']

    # match/case not supported until Python 3.10
    payload = None
    if source_type == 'snmp':
        payload = json.loads(event['_raw'])['data']
    if source_type == 'syslog':
        payload = event['_raw']

    if payload is None:
        return

    msg = IP(dst=destination, src=original_host) / UDP(dport=dport) / Raw(payload)
    send(msg, verbose=SCAPY_VERBOSE)


async def forwarder(request: Request):
    try:
        events = await request.json()
        for event in events:
            await handle_event(event)
    except Exception as e:
        print(f'Exception: {str(e)}')

    return JSONResponse({'status': 'ok'})


middleware = [
    Middleware(AuthMiddleware),
    Middleware(GunzipMiddleware)
]

config = Config('.env')
API_TOKEN = config('API_TOKEN', cast=str, default='')
APP_DEBUG = config('APP_DEBUG', cast=bool, default=False)
SCAPY_VERBOSE = config('SCAPY_VERBOSE', cast=bool, default=False)

app = Starlette(debug=APP_DEBUG, routes=[
    Route('/', forwarder, methods=["POST"]),
], middleware=middleware)
