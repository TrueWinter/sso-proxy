# SSO Proxy

This is a very simple JWT-based SSO server that uses Google as an identity provider. It was written to ease the development process of new internal apps where I work and to allow employees to log into internal apps using their business Google accounts.

The login flow is quite simple:
- A user wants to log into an internal app
- The app redirects the user to `sso-proxy.url/sso/appname?state=randomness`
- SSO Proxy verifies that the app exists and that the state is set, then redirects the user to Google for authentication. The state passed to Google includes:
	- `s`: a state value generated by SSO Proxy
	- `r`: the name of the app
	- `a`: the state value from the app
	- `h`: an MD5 hash of the above
- After the user authenticates with Google, they are redirected back to SSO Proxy where the state is verified and the validity of the access token is checked. The user is then redirected back to the app with the following JWT (valid for 30 seconds) passed in the `token` query parameter:
	- `email`: the user's email
	- `state`: the state the app generated