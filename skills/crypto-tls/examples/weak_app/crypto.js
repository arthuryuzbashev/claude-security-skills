// Fictional Node helpers with weak crypto. Fake values only.
const crypto = require("crypto");
const https = require("https");

const sessionToken = Math.random().toString(36).slice(2); // session id
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
const fileSum = crypto.createHash("md5").update(buf).digest("hex");
const legacy = crypto.createCipheriv("des-ede3-cbc", key24, iv8);
const agent = new https.Agent({ rejectUnauthorized: false });
const jwtSecret = "s3cr3t-signing-value-for-demo-only";
const wrapped = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, buf);
const derived = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512");
const pwHash = await bcrypt.hash(password, 8);
const client = https.request({ host, minVersion: "TLSv1" });
