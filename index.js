const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const express = require('express');
const session = require('express-session');
const MemFileStore = require('express-memfilestore')(session);
const jwt = require('jsonwebtoken');
const safeCompare = require('safe-compare');
/** @type {import('axios').default} */
const axios = require('axios');
const bodyParser = require('body-parser');

const util = require('./util.js');
const config = require('./config.json');

const app = express();

const keyPath = path.join(__dirname, 'oauth.json');
let keys = {
	redirect_uris: ['']
};
if (fs.existsSync(keyPath)) {
	keys = require(keyPath).web;
}

const oauth2Client = new google.auth.OAuth2(
	keys.client_id,
	keys.client_secret,
	config.callbackUrl || keys.redirect_uris[0]
);

google.options({
	auth: oauth2Client
});

for (let app in config.redirects) {
	if (config.redirects[app].jwt.overrides['ssoproxy:require']) {
		config.redirects[app].jwt.overrides = require(path.join(__dirname,
			config.redirects[app].jwt.overrides['ssoproxy:require']));
	}
}

var sessionStore = new MemFileStore({
	checkPeriod: 30 * 60 * 1000,
	savePeriod: 5 * 60 * 1000,
	saveFile: path.join(__dirname, 'sessions.json')
});

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
	secret: config.secret,
	resave: false,
	name: 'ssoproxy',
	saveUninitialized: false,
	store: sessionStore,
	cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
}));
app.use(express.static('public'));

app.locals.companyName = config.companyName;

app.get('/', (req, res) => {
	res.render('index', {
		accounts: (req.session && req.session.accounts) && req.session.accounts
	});
});

/**
 * @param {express.Request} req The request
 * @param {express.Response} res The response
 * @param {string} app The app
 * @param {string} state The state
 * @param {string} email The user's email
 */
function successfulLogin(req, res, app, state, email) {
	if (!(app in config.redirects)) {
		res.status(400).end('Unknown app');
		return;
	}

	if (!req.session || !req.session.accounts) {
		res.status(401).end('Not logged in');
		return;
	}

	if (!req.session.accounts[email]) {
		res.status(401).end('Not logged in to that account');
		return;
	}

	var tokenFields = handlePlaceholderVariable(req, res, app, state, email, Object.assign({}, config.redirects[app].jwt.default));
	var overrides = Object.assign({}, config.redirects[app].jwt.overrides);

	for (let o in overrides) {
		if (overrides[o][tokenFields[o]]) {
			Object.assign(tokenFields, overrides[o][tokenFields[o]]);
		}
	}

	tokenFields = handlePlaceholderVariable(req, res, app, state, email, tokenFields);
	let token = jwt.sign(tokenFields, config.redirects[app].secret, {
		expiresIn: '30s'
	});

	let queryParams = handlePlaceholderVariable(req, res, app, state, email, Object.assign({}, config.redirects[app].query));
	queryParams = JSON.parse(JSON.stringify(queryParams)
		.replace(/{jwt}/g, token)
	);
	let url = new URL(config.redirects[app].url);
	for (let q in queryParams) {
		url.searchParams.append(q, queryParams[q]);
	}

	console.log('[LOGIN]', new Date(), email, app);
	res.redirect(url.href);
}

/**
 * @param {express.Request} req The request
 * @param {express.Response} res The response
 * @param {string} app The app
 * @param {string} state The state
 * @param {string} email The user's email
 * @param {Object} tokenFields Fields
 * @returns {Object} Token
 */
function handlePlaceholderVariable(req, res, app, state, email, tokenFields) {
	// Match is only due to how regex replace works, but these functions may be used in other parts of the code later
	function getOauthData(match, param) {
		if (!param) param = match;
		return req.session.accounts[email].account[param];
	}

	return JSON.parse(JSON.stringify(tokenFields)
		.replace(/{oauth\.([a-zA-Z0-9-_.]+)}/g, getOauthData)
		.replace(/{state}/g, state)
	);
}

app.get('/sso/:app', (req, res) => {
	if (!(req.params.app in config.redirects)) {
		return res.status(400).end('Unknown app');
	}

	if (!req.query.state) {
		return res.status(400).end('State required');
	}

	if (!req.session || !req.session.state) {
		req.session.state = util.randomString(16);
	}

	let h = crypto.createHash('md5')
		.update(req.session.state + req.params.app +
			req.query.state + config.secret)
		.digest('base64url');

	if (!req.session.accounts || Object.keys(req.session.accounts).length === 0) {
		return res.redirect(`/oauth/google?app=${req.params.app}&state=${req.query.state}&h=${h}`);
	}

	res.render('select-account', {
		app: req.params.app,
		appState: req.query.state,
		hash: h,
		accounts: req.session.accounts
	});
});

app.post('/login-with-current-account', (req, res) => {
	if (!(req.body.email && req.body.app && req.body.state && req.body.hash && req.body.loginToken)) {
		return res.status(400).end('Required data not present');
	}

	if (!(req.body.app in config.redirects)) {
		return res.status(400).end('Unknown app');
	}

	if (!req.body.state) {
		return res.status(400).end('State required');
	}

	let h = crypto.createHash('md5')
		.update(req.session.state + req.body.app +
			req.body.state + config.secret)
		.digest('base64url');

	if (!safeCompare(req.body.hash, h)) {
		return res.status(400).end('Invalid hash');
	}

	let account = req.session.accounts[req.body.email];
	if (!account) {
		return res.status(401).end('Not logged in to that account');
	}

	if (!safeCompare(req.body.loginToken, account.loginToken)) {
		return res.status(401).end('Invalid login token');
	}

	successfulLogin(req, res, req.body.app, req.body.state, account.account.email);
});

app.get('/oauth/google', (req, res) => {
	if (!(req.query.app && req.query.state && req.query.h)) {
		return res.status(400).end('State, app, and hash are required');
	}

	let h = crypto.createHash('md5')
		.update(req.session.state + req.query.app +
			req.query.state + config.secret)
		.digest('base64url');

	if (!safeCompare(req.query.h, h)) {
		return res.status(400).end('Invalid hash');
	}

	let state = Buffer.from(JSON.stringify({
		s: req.session.state,
		r: req.query.app,
		a: req.query.state,
		h
	})).toString('base64url');

	let authUrl = oauth2Client.generateAuthUrl({
		access_type: 'online',
		scope: [
			'profile',
			'email'
		],
		state,
		hd: config.domain
	});

	res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
	if (!(req.query.code && req.query.state)) {
		return res.status(400).end('Auth code and state are required');
	}

	if (!req.session || !req.session.state) {
		return res.status(400).end('Invalid request');
	}

	try {
		let code = req.query.code;
		let state = JSON.parse(Buffer.from(req.query.state, 'base64url').toString());

		let sessState = req.session.state;
		if (sessState !== state.s) {
			return res.status(400).end('Invalid state');
		}

		if (!(state.r in config.redirects)) {
			return res.status(400).end('Unknown app');
		}

		let h = crypto.createHash('md5')
			.update(state.s + state.r + state.a + config.secret)
			.digest('base64url');

		if (!safeCompare(state.h, h)) {
			return res.status(400).end('Invalid hash');
		}

		let { tokens } = await oauth2Client.getToken(code);
		let t = await oauth2Client.getTokenInfo(tokens.access_token);

		if (!t || !t.email) {
			return res.status(400).end('Failed to get user email');
		}

		if (!t.email.endsWith(`@${config.domain}`)) {
			return res.status(400).end('Incorrect email domain');
		}

		try {
			// Was going to use the people API (from the googleapis module) for this,
			// but couldn't find a working way to pass the access token.
			let account = (await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
				headers: {
					Authorization: `Bearer ${tokens.access_token}`
				}
			})).data;

			if (!req.session.accounts) {
				req.session.accounts = {};
			}
			req.session.accounts[account.email] = {};
			req.session.accounts[account.email].account = account;
			req.session.accounts[account.email].loginToken = await util.cryptoRandomString(32, 'base64url');
			return successfulLogin(req, res, state.r, state.a, account.email);
		} catch (err) {
			return res.status(500).end('Failed to get account information');
		}
	} catch (err) {
		if (!['invalid_grant'].includes(err.message)) {
			console.error(err);
		}
		return res.status(500).end('Failed to verify login');
	}
});

app.get('/logout', (req, res) => {
	if (req.session) {
		req.session.destroy(() => {
			res.end('Logged out');
		});

		return;
	}

	res.end('Logged out');
});

app.post('/logout', (req, res) => {
	if (!(req.body.email && req.body.token && req.body.return)) {
		return res.status(400).end('Invalid request');
	}

	if (!req.session && req.session.accounts) {
		return res.redirect(req.body.return);
	}

	let account = req.session.accounts[req.body.email];
	if (!account) {
		return res.redirect(req.body.return);
	}

	if (safeCompare(req.body.token, account.loginToken)) {
		delete req.session.accounts[req.body.email];
	} else {
		return res.status(400).end('Invalid token');
	}

	res.redirect(req.body.return);
});

app.listen(config.port, () => {
	console.log(`Listening on port ${config.port}`);
});

process.on('uncaughtException', (err) => {
	console.error('Uncaught exception', err);
});

process.on('unhandledRejection', (err) => {
	console.error('Unhandled rejection', err);
});