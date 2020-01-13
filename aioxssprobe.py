import asyncio
import sys
import json
from urllib import parse

async def get_urls(loop, stream):
    reader = asyncio.StreamReader(loop=loop)
    reader_protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: reader_protocol, stream)

    while True:
        line = await reader.readline()
        if not line:
            break

        line = line.decode('utf-8')
        if line.startswith('{'):
            # interpret as json object
            obj = json.loads(line)
            url = obj['url'].strip()
        else:
            url = line.strip()

        yield url

async def probe_incoming_urls(loop):
    processed_urls = set()
    async for url in get_urls(loop, sys.stdin):
        if url in processed_urls:
            continue

        async for result in probe_url(url):
            print(result)

        processed_urls.add(url)

async def probe_url(url):
    '''only probe using query params for now'''
    probes = [
        QueryParamsProbe(url),
    ]

    tasks = [asyncio.create_task(p.probe()) for p in probes]
    await asyncio.gather(*tasks)

    for probe in probes:
        for result in probe.results():
            yield result


class QueryParamsProbe:
    def __init__(self, url):
        self._url = url

    async def probe(self):
        pass

    def results(self):
        yield 'result1'
        yield 'result2'

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    loop.run_until_complete(probe_incoming_urls(loop))
