const crypto = require('crypto');
const { promisify } = require('util');

module.exports.randomString = function(length = 16) {
	var result = '';
	var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var charactersLength = characters.length;
	for (var i = 0; i < length; i++) {
		result += characters.charAt(Math.floor(Math.random() * charactersLength));
	}
	return result;
};

/**
 * @param {number} bytes Bytes
 * @param {BufferEncoding} encoding Encoding
 * @returns {string} Random string
 */
module.exports.cryptoRandomString = async function(bytes = 16, encoding = 'hex') {
	return (await promisify(crypto.randomBytes)(bytes)).toString(encoding);
};
