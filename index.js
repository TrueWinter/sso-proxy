const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const express = require('express');
const session = require('express-session');
const MemFileStore = require('express-memfilestore')(session);
const jwt = require('jsonwebtoken');
const safeCompare = require('safe-compare');
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
	keys.redirect_uris[0]
);

google.options({
	auth: oauth2Client
});

var sessionStore = new MemFileStore({
	checkPeriod: 30 * 60 * 1000,
	savePeriod: 5 * 60 * 1000,
	saveFile: path.join(__dirname, 'sessions.json')
});
app.set('trust proxy', 1);
app.use(session({
	secret: config.secret,
	resave: false,
	name: 'ssoproxy',
	saveUninitialized: false,
	store: sessionStore,
	cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
}));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.get('/', (req, res) => {
	res.render('index', {
		email: (req.session && req.session.email) && req.session.email,
		companyName: config.companyName
	});
});

/**
 * @param {express.Request} req The request
 * @param {express.Response} res The response
 * @param {string} app The app
 * @param {string} state The state
 */
function successfulLogin(req, res, app, state) {
	if (!(app in config.redirects)) {
		res.status(400).end('Unknown app');
		return;
	}

	if (!req.session || !req.session.email) {
		res.status(401).end('Not logged in');
	}

	let opts = {
		expiresIn: '30s'
	};
	let token = jwt.sign({
		email: req.session.email,
		state
	}, config.redirects[app].secret, opts);

	res.redirect(`${config.redirects[app].url}?token=${token}`);
}

app.get('/sso/:app', (req, res) => {
	if (!(req.params.app in config.redirects)) {
		return res.status(400).end('Unknown app');
	}

	if (!req.query.state) {
		return res.status(400).end('State required');
	}

	if (req.session.email) {
		return successfulLogin(req, res, req.params.app, req.query.state);
	}

	req.session.state = util.randomString(16);

	let state = Buffer.from(JSON.stringify({
		s: req.session.state,
		r: req.params.app,
		a: req.query.state,
		h: crypto.createHash('md5')
			.update(req.session.state + req.params.app +
				req.query.state + config.secret)
			.digest('base64')
	})).toString('base64url');

	let authUrl = oauth2Client.generateAuthUrl({
		access_type: 'online',
		scope: [
			'profile',
			'email'
		],
		state,
		hd: config.hd
	});

	res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
	if (req.session && req.session.email) {
		return res.status(400).end('You are already logged in to the login server');
	}

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
			.digest('base64');

		if (!safeCompare(state.h, h)) {
			return res.status(400).end('Invalid hash');
		}

		let { tokens } = await oauth2Client.getToken(code);
		let t = await oauth2Client.getTokenInfo(tokens.access_token);

		if (!t || !t.email) {
			return res.status(400).end('Failed to get user email');
		}

		if (!t.email.endsWith(`@${config.hd}`)) {
			return res.status(400).end('Incorrect email domain');
		}

		console.log(new Date(), t.email, state.r);
		req.session.email = t.email;
		return successfulLogin(req, res, state.r, state.a);
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

app.listen(config.port, () => {
	console.log(`Listening on port ${config.port}`);
});

process.on('uncaughtException', (err) => {
	console.error('Uncaught exception', err);
});

process.on('unhandledRejection', (err) => {
	console.error('Unhandled rejection', err);
});