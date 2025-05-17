import base64
import requests


class OktaTokenGenerator:

    #   cache = TTLCache(maxsize=10, ttl=1800)

    #   @cached(cache)
    #   def get_cached_data(key):
    #       return getOktaToken(key)

    def getOktaToken(paramList):
        oktaUrl = paramList[0]
        clientID = paramList[1]
        clientSecret = paramList[2]
        clientIDSecrect = clientID + ":" + clientSecret

        try:
            clientIDSecrect_bytes = clientIDSecrect.encode()
            authorization = "Basic" + base64.b64encode(clientIDSecrect_bytes).decode()
            headerMap = {
                'Authorization': authorization,
                'Accept': 'application/json',
                'Content-type': 'application/x-www-form-urlencoded'
            }
            response = requests.post(oktaUrl, headers=headerMap, data='&grant_type=client_credentials')
            responseStatus = response.status_code

            if responseStatus == 200:
                jsonresponse = response.json()
                AccessToken = jsonresponse['access_token']
                Access_Token = "Bearer " + AccessToken
                return (Access_Token)
            else:
                return ("Bearer Some-Exception-occured-while-getting-the-okta-token")

        except Exception as e:
            return ("Bearer Some-Exception-occured-while-getting-the-okta-token")


def okta_token_generator():
    oauth_client_id = input("Enter the oauth client id: ")
    oauth_client_secret = input("Enter the oauth client secret: ")
    oauth_server_uri = input("Enter the oauth client uri: ")
    paramList = [oauth_server_uri, oauth_client_id, oauth_client_secret]
    Token = OktaTokenGenerator.getOktaToken(paramList)
    return Token


if __name__ == "__main__":
    print(okta_token_generator())