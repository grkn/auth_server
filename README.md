# Template for fully customized authentication and authorization server

## Authentication and Authorization Type

It supports implicit flow and client credentials.
Application supports:
  - oAuth2 Server supports implicit flow (login in and get JSessionID to access token endpoint)
  - Authentication with client credentials (If you have valid SessionID, you can get accessToken and refreshToken).

## General Flow.

Login in custom login screen.

Authenticate with username password.

Automatically get JSESSIONID from cookie

Send request to oauth2/token endpoint with JSESSIONID in cookie

Get accessToken and refreshToken with client credentials.

Then simply you can send a request to backend with accessToken or simply refresh your token with refreshToken
  - You can send request to RestController with Authorization header "Authorization: Bearer {accessToken}"
  - You can send request to RefreshToken with client credentials for refresh token.

## Tricky points

I used default user for simplification and it is hard coded in the code:
  - Username: user
  - Password: password
  - clientId: user
  - clientSecret: password.
  - clientName: tgf

Also secret key is generated in runtime when you restart your application so token needs to be taken in each restart. For better usaged just store your secretKey somewhere and fetch it. Else it throws unverified token and can not verify signature.

## Application specification

- Springboot 3.2.3 is used as latest spring boot version
- 
- Java 21 is used for implementation
- 
- Maven is used for dependecy management.
- 
- Spring authorization server is used for endpoints and intercepted request in authentication manager class.

## Endpoints

1- POST http://localhost:9090/oauth2/token -> can be used for refreshing token or retrieving tokens.

2- GET http://localhost:9090/tgf/data -> It returns back data of user in authentication context.

3- GET http://localhost:9090/login.html -> simple login page

4- POST http://localhost:9090/client/authenticate -> login form is posted to this endpoint and username password authentication is done.


## Missing points

I will integrate with h2.

I will handle exceptions in appropriate way.

I will add optionality of encryption of access token.

I will fill mocked logic with appropriate way.

I used inmemory user for template and you can simply change it to h2 or any other table with replacing repositories.

## Recommendation

I recommend that you can read https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/.



