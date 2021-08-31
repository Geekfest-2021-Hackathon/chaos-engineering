import json

json_file = open("openapi.json")
data = json.load(json_file)

for path in data["paths"]:
    print(f"Path: {path}")
    print(f"Details: {data['paths'][path]}")
    print()
