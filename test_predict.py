import requests

url = "http://127.0.0.1:7860/predict"
data = {
    "values": [0.2, 1.5, 3.1]
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response JSON:", response.json())
