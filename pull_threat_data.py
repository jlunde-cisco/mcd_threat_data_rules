import requests
import json

# Function to fetch data from the API and return a list of extracted dictionaries
def fetch_and_extract_data(baseUrl, accountName, token):
    url = f"{baseUrl}/api/v1/threatresearch/get"
    headers = {
        'Authorization': f'Bearer {token}',
    }
    accountname = accountName
    results = []

    # Initial request
    payload = {
        "common": {
            "acctName": str(accountname)
        },
        "pageInfo": {
            "pageSize": 100,
            "startPageToken": "0"
        },
        "criterion": {
            "criterion": [
                {
                    "field": {
                        "field": "TYPE"
                    },
                    "values": [
                        "IPS"
                    ]
                },
                {
                    "field": {
                        "field": "VENDOR"
                    },
                    "values": [
                        "VENDOR_TALOS"
                    ]
                }
            ]
        }
    }

    while True:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        parsed_response = response.json()

        for item in parsed_response['details']:
            details_from_elastic = item.get('detailsFromElastic', {})
            message = details_from_elastic.get("message")
            rule_content = details_from_elastic.get("ruleContent")
            extracted_dict = {
                "message": message,
                "ruleContent": rule_content
            }
            results.append(extracted_dict)

        if 'more' in parsed_response['pageInfo']:
            payload["pageInfo"]["startPageToken"] = str(parsed_response['pageInfo']['nextPageToken'])
        else:
            break

    return results

def write_to_json(data, filename):
    # Write the extracted data to a JSON file
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

def getToken(baseUrl, accountName, apiKey, apiSecret):
    url = f"{baseUrl}/api/v1/user/gettoken"

    payload = json.dumps({
        "common": {
        "acctName": str(accountName),
        "source": "RESTAPI",
        "clientVersion": "Valtix-2022"
        },
        "apiKeyID": str(apiKey),
        "apiKeySecret": str(apiSecret)
        })
    headers = {
        'Content-Type': 'application/json'
        }

    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json()['accessToken']

if __name__ == "__main__":
    # Generate API key from your multicloud defense dashboard and fill in the below variables (accountName, baseURL, apiKey, and apiSecret)
    baseUrl = "https://freetier.svc.valtix.com"
    accountName = ""
    apiKey = ""
    apiSecret = ""

    # Generate an API token for the session
    token = str(getToken(baseUrl, accountName, apiKey, apiSecret))

    # Make the API call to extract the threat data from Talos
    extracted_data = fetch_and_extract_data(baseUrl, accountName, token)

    # Specify the filename for the JSON file
    json_filename = "extracted_values.json"
    write_to_json(extracted_data, json_filename)

    print(f"The extracted values have been written to '{json_filename}'")
