#!/usr/bin/env python3.7

import json
from urllib import parse
from collections import defaultdict
import random
import string
import requests
import bs4
import re

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
    try:
        body = requests.get(test_url).text
    except Exception as e:
        print(f'ERROR: {e}')
        return

    for k, vs in test_params.items():
        for v in vs:
            if v in body:
                contexts = get_param_contexts(v, body)
                for ctx in contexts:
                    confidence = ctx.verify(parsed_url, test_params, k, v)
                    yield (build_url(parsed_url, {k: ['X']}), 'GET', k, confidence, type(ctx).__name__)

def verify_query_param_reflection(parsed_url, params, name, old_value, new_value):
    # copy params and values to avoid modifying values that might
    # be in use by some other part of the program
    new_params = dict(params)
    new_values = set(new_params[name])
    new_values.remove(old_value)
    new_values.add(new_value)
    new_params[name] = new_values

    try:
        url = build_url(parsed_url, new_params)
        response = requests.get(url)
        body = response.text
        return new_value in body
    except Exception as e:
        print(f'ERROR: {e}')
        return False

def get_param_contexts(param_value, body):
    soup = bs4.BeautifulSoup(body, 'html.parser')
    contexts = set()

    in_text = soup.find_all(lambda tag: type(next(tag.children, None)) is bs4.element.NavigableString and param_value in tag.contents[0])
    for tag in in_text:
        if tag.name == 'script':
            for line in (l for l in str(tag).split('\n') if param_value in l):
                results = {}
                if single := re.search("'.*" + param_value + ".*'", line):
                    results['SCRIPT_SINGLEQUOTE'] = single.group(0)
                if double := re.search('".*' + param_value + '.*"', line):
                    results['SCRIPT_DOUBLEQUOTE'] = double.group(0)
                if execq := re.search(r'`.*' + param_value + '.*`', line):
                    results['SCRIPT_EXECQUOTE'] = execq.group(0)

                if not results:
                    contexts.add('SCRIPT_NOQUOTES')
                    continue

                quote_type = sorted(((t, len(match)) for t, match in results.items()), key=lambda x: x[1])[0][0]
                contexts.add(quote_type)
        else:
            contexts.add('TEXT')

    in_attr = soup.find_all(lambda tag: any(param_value in x for x in tag.attrs.values())) 
    if in_attr:
        for tag in in_attr:
            single_quote_regex = '="[^"]*?' + param_value + '.*?"'
            if re.search(single_quote_regex, str(tag)):
                contexts.add('ATTRIBUTE_DOUBLEQUOTE')
                continue
            double_quote_regex = "='[^']*?" + param_value + ".*?'"
            if re.search(double_quote_regex, str(tag)):
                contexts.add('ATTRIBUTE_SINGLEQUOTE')
                continue
            no_quote_regex = r"""\s[^=]+=[^"'\s]*?""" + param_value + r"""[^>\s]*"""
            if re.search(no_quote_regex, str(tag)):
                contexts.add('ATTRIBUTE_NOQUOTE')
                continue

    if not contexts:
        contexts.add('UNDETERMINED')

    return [string_to_context(ctx) for ctx in contexts]

def build_url(parsed_url, params):
    query_string = '&'.join('&'.join(f'{k}={v}' for v in vs) for k, vs in params.items())
    url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}#{parsed_url.fragment}'

    return url

class ScriptSingleQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"</script>{value}"
        script = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if script:
            return 100

        new_value = f"'{value}"
        single_quote = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if single_quote:
            return 100

        new_value = f"<>{value}"
        double_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_angle:
            return 50


        new_value = f"<{value}"
        open_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if open_angle:
            return 25

        new_value = f">{value}"
        close_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if close_angle:
            return 25

        return 1

class ScriptDoubleQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"</script>{value}"
        script = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if script:
            return 100

        new_value = f'"{value}'
        double_quote = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_quote:
            return 100

        new_value = f"<>{value}"
        double_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_angle:
            return 50

        new_value = f"<{value}"
        open_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if open_angle:
            return 25

        new_value = f">{value}"
        close_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if close_angle:
            return 25

        return 1

class ScriptExecQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"</script>{value}"
        script = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if script:
            return 100

        new_value = f'`{value}'
        exec_quote = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if exec_quote:
            return 100

        new_value = '${prompt(1)}'+value
        exec_str = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if exec_str:
            return 100

        new_value = f"<>{value}"
        double_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_angle:
            return 50

        new_value = f"<{value}"
        open_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if open_angle:
            return 25

        new_value = f">{value}"
        close_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if close_angle:
            return 25

        return 1

class ScriptNoQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"</script>{value}"
        script = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if script:
            return 100

        new_value = '`${prompt(1)}`'+value
        exec_str = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if exec_str:
            return 100

        new_value = f"<>{value}"
        double_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_angle:
            return 50

        new_value = f"<{value}"
        open_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if open_angle:
            return 25

        new_value = f">{value}"
        close_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if close_angle:
            return 25

        return 1

class TextContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"<script>{value}</script>"
        script = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if script:
            return 100

        new_value = f"<svg/onload={value}>"
        svg = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if svg:
            return 100

        new_value = f"<{value}>"
        in_angles = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if in_angles:
            return 50

        new_value = f"<{value}"
        open_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if open_angle:
            return 25

        new_value = f">{value}"
        close_angle = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if close_angle:
            return 25

        return 1

class AttributeDoubleQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f'"{value}'
        double_quote = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if double_quote:
            return 100

        return 1

class AttributeSingleQuoteContext:
    def verify(self, parsed_url, params, name, value):
        new_value = f"'{value}"
        single_quote = verify_query_param_reflection(parsed_url, params, name, value, new_value)
        if single_quote:
            return 100

        return 1

class AttributeNoQuoteContext:
    def verify(self, parsed_url, params, name, value):
        return 100

class UndeterminedContext:
    def verify(self, parsed_url, params, name, value):
        return 50

def string_to_context(string):
    return {
        "SCRIPT_SINGLEQUOTE": ScriptSingleQuoteContext,
        "SCRIPT_DOUBLEQUOTE": ScriptDoubleQuoteContext,
        "SCRIPT_EXECQUOTE": ScriptExecQuoteContext,
        "SCRIPT_NOQUOTES": ScriptNoQuoteContext,
        "TEXT": TextContext,
        "ATTRIBUTE_SINGLEQUOTE": AttributeSingleQuoteContext,
        "ATTRIBUTE_DOUBLEQUOTE": AttributeDoubleQuoteContext,
        "ATTRIBUTE_NOQUOTE": AttributeNoQuoteContext,
        "UNDETERMINED": UndeterminedContext,
    }[string]()

if __name__ == '__main__':
    urls_source = get_urls()

    reported = set()

    for url in urls_source:
        if not (url.startswith('http://') or url.startswith('https://')):
            continue

        try:
            for report in probe_xss(url):
                if report in reported:
                    continue

                print(json.dumps({
                    'url': report[0],
                    'method': report[1],
                    'reflected_param': report[2],
                    'confidence': report[3],
                    'context': report[4],
                }))

                reported.add(report)
        except Exception as e:
            print(f'ERROR: {e}')
