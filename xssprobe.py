#!/usr/bin/env python3.7

import json
from urllib import parse
from collections import defaultdict
import random
import string
import requests

_RANDOM_CHAR_SET = string.ascii_lowercase
_RANDOM_CHAR_COUNT = 12

def get_urls():
    while True:
        try:
            in_line = input()
        except EOFError:
            break

        if in_line.startswith('{'):
            # interpret as json object
            obj = json.loads(in_line)
            url = obj['url']
        else:
            url = in_line

        yield url

def probe_xss(url):
    yield from query_params_probe(url)

def query_params_probe(url):
    parsed_url = parse.urlparse(url)

    if parsed_url.query == '':
        return

    query_params = parse.parse_qs(parsed_url.query)
    test_params = defaultdict(set)
    for k, vs in query_params.items():
        for v in vs:
            random_value = ''.join(random.choice(_RANDOM_CHAR_SET) for _ in range(_RANDOM_CHAR_COUNT))
            test_params[k].add(random_value)
                
    test_url = build_url(parsed_url, test_params)
    body = requests.get(test_url).text

    for k, vs in test_params.items():
        for v in vs:
            if v in body:
                verified = verify_query_param_reflection(parsed_url, test_params, k, v)
                reflected_url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{k}=X'

                if verified:
                    yield (reflected_url, 'GET', k, True)
                else:
                    yield (reflected_url, 'GET', k, False)

def verify_query_param_reflection(parsed_url, params, name, value):
    new_value = value + '\'"><'

    # copy params and values to avoid modifying values that might
    # be in use by some other part of the program
    new_params = dict(params)
    new_values = set(new_params[name])
    new_values.remove(value)
    new_values.add(new_value)
    new_params[name] = new_values

    try:
        url = build_url(parsed_url, new_params)
        response = requests.get(url)
        body = response.text
        return new_value in body
    except Exception as e:
        print(f'ERROR: {e}')

def build_url(parsed_url, params):
    query_string = '&'.join('&'.join(f'{k}={v}' for v in vs) for k, vs in params.items())
    url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}#{parsed_url.fragment}'

    return url

if __name__ == '__main__':
    urls_source = get_urls()

    reported = set()

    for url in urls_source:
        if not (url.startswith('http://') or url.startswith('https://')):
            continue

        for report in probe_xss(url):
            if report in reported:
                continue

            print(json.dumps({
                'url': report[0],
                'method': report[1],
                'reflected_param': report[2],
                'confirmed': report[3],
            }))

            reported.add(report)
