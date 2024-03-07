# Template for Fully customized authentication and authorization server


## General Flow.

Login in custom login screen.

Authenticate with username password.

Automatically get JSESSIONID from cookie

Send request to oauth2/token endpoint with JSESSIONID in cookie

Get accessToken and refreshToken with client credentials.

Then simply you can send a request to backend with accessToken or simply refresh your token with refreshToken

