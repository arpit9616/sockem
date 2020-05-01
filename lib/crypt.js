/* 
 * (C) 2015 - 2018 TekMonks. All rights reserved.
 */
if (!global.CONSTANTS) global.CONSTANTS = require(__dirname + "/constants.js");	// to support direct execution

const crypto = require("crypto");
const crypt = require(CONSTANTS.CRYPTCONF);

const encrypt = (text, key = crypt.key) => {
	const iv = Buffer.from(crypto.randomBytes(16)).toString("hex").slice(0, 16);
	const password_hash = crypto.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const cipher = crypto.createCipheriv(CONSTANTS.CRPT_ALGO, password_hash, iv);
	let crypted = cipher.update(text, Buffer.isBuffer(text)?undefined:"utf8", "hex");
	crypted += cipher.final("hex");
	return crypted + iv;
};

const decrypt = (textOrBuffer, key, needBuffer) => {
	if (!key) key = crypt.key; if (!needBuffer) needBuffer = false; 
	const text = Buffer.isBuffer(textOrBuffer) ? textOrBuffer.toString("utf8") : textOrBuffer;
	const iv = text.slice(text.length - 16, text.length);
	const encrypted = text.substring(0, text.length - 16);
	const password_hash = crypto.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const decipher = crypto.createDecipheriv(CONSTANTS.CRPT_ALGO, password_hash, iv);
	let decrypted = decipher.update(encrypted, "hex", needBuffer?undefined:"utf8");
	decrypted += decipher.final(needBuffer?undefined:"utf8");
	return decrypted;
};

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
