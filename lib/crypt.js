/** 
 * AES-256 encrypter and decrypter.
 * (C) 2015 - 2018 TekMonks. All rights reserved.
 */
if (!global.CONSTANTS) global.CONSTANTS = require(__dirname + "/constants.js");	// to support direct execution

const cryptmod = require("crypto");
const crypt = require(CONSTANTS.CRYPTCONF);

/**
 * Encrypts the given text or buffer, AES-256.
 * @param {string|Buffer} text Input as string or buffer
 * @param {string} key The key as string
 * @returns {string|Buffer} If string was input then output is encrypted hex string, else output is encrypted buffer
 */
const encrypt = (text, key = crypt.key) => {
	const iv = Buffer.from(cryptmod.randomBytes(16)).toString("hex").slice(0, 16);
	const password_hash = cryptmod.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const cipher = cryptmod.createCipheriv(CONSTANTS.CRPT_ALGO, password_hash, iv);
	let crypted = cipher.update(text, Buffer.isBuffer(text)?null:"utf8", "hex");
	crypted += cipher.final("hex");
	return Buffer.isBuffer(text)?Buffer.from(crypted + iv):crypted + iv;
}

/**
 * Decrypts the given string or buffer. AES-256.
 * @param {string|Buffer} textOrBuffer Input as string or buffer
 * @param {string} key  The key as string
 * @returns {string|Buffer} If string was input then output is encrypted hex string, else output is encrypted buffer
 */
const decrypt = (textOrBuffer, key) => {
	if (!key) key = crypt.key; needBuffer = Buffer.isBuffer(textOrBuffer);
	const text = needBuffer ? textOrBuffer.toString("utf8") : textOrBuffer;
	const iv = text.slice(text.length - 16, text.length);
	const encrypted = text.slice(0, text.length - 16);
	const password_hash = cryptmod.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const decipher = cryptmod.createDecipheriv(CONSTANTS.CRPT_ALGO, password_hash, iv);
	let decrypted = decipher.update(encrypted, "hex", needBuffer?null:"utf8");
	decrypted = needBuffer?Buffer.concat([decrypted, decipher.final()]):decrypted+decipher.final("utf8");
	return needBuffer?Buffer.from(decrypted):decrypted;
}

if (require.main === module) {
	const args = process.argv.slice(2);

	if (args.length < 2) {
		console.log("Usage: crypt <encyrpt|decrypt> <text to encrypt or decrypt>");
		process.exit(1);
	}

	console.log(eval(args[0])(args[1]));
}

module.exports = {
	encrypt,
	decrypt
};
