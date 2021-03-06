import json
import requests

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

    try:
        response = requests.get(url)
    except:
        # log error message
        continue

    output = json.dumps({
        'text': response.text,
    })

    print(output)
