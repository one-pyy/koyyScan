import json

def output_json(data: dict):
    with open('result.json', 'w') as f:
        json.dump(data, f, indent=2)