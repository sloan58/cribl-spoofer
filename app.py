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
        if auth_header is None or auth_header != f'Bearer {TOKEN}':
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

    # match/case not supported until Python 3.10
    if source_type == 'snmp':
        payload = json.loads(event['_raw'])['data']
        dport = 162
    if source_type == 'syslog':
        payload = event['_raw']
        dport = 514

    msg = IP(dst=destination, src=original_host) / UDP(dport=dport) / Raw(payload)

    #print(msg.show())
    send(msg)


async def forwarder(request: Request):
    events = await request.json()

    for event in events:
        await handle_event(event)

    return JSONResponse({'status': 'ok'})


middleware = [
    Middleware(AuthMiddleware),
    Middleware(GunzipMiddleware)
]

config = Config('.env')
TOKEN = config('TOKEN', cast=str, default='')

app = Starlette(debug=True, routes=[
    Route('/', forwarder, methods=["POST"]),
], middleware=middleware)
