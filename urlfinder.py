#!/usr/bin/env python3.7
from urllib.parse import urlparse
import re
import json

URL_REGEX = re.compile('https?://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?')

class Scope:
    def __init__(self, domains):
        self._domains = set(domains)

    def is_in_scope(self, host):
        if host in self._domains:
            return True

        scope_sufixes = set('.' + s for s in self._domains)
        for s in scope_sufixes:
            if host.endswith(s):
                return True

        return False

    def __contains__(self, host) :
        return self.is_in_scope(host)


class UrlFinder:
    def __init__(self, scope):
        self._scope = scope

    def find_urls(self, text):
        urls = (m.group(0) for m in URL_REGEX.finditer(text))
        for url in urls:
            hostname = urlparse(url).hostname
            if hostname in self._scope:
                yield url


def get_text():
    while True:
        try:
            in_line = input()
        except EOFError:
            break

        if in_line.startswith('{'):
            # interpret as json object
            obj = json.loads(in_line)
            text = obj['text']
        else:
            text = in_line

        yield text


def find_urls(text_source, url_finder):
    found_urls = set()

    for text in text_source:
        urls = set(url_finder.find_urls(text)) - found_urls
        yield from urls

        found_urls |= urls

if __name__ == '__main__':
    import sys

    scope = Scope(sys.argv[1:])
    url_finder = UrlFinder(scope)
    urls = find_urls(get_text(), url_finder)

    for url in urls:
        print(json.dumps({
            'url': url,
        }))
