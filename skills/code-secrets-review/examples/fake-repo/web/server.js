// Fake Express server for the Aegis examples. Nothing here is real.
const { exec, execFile } = require("child_process");
const crypto = require("crypto");

function ping(host) {
  exec(`ping -c 1 ${host}`);
  execFile("ping", ["-c", "1", host]);
}

function render(el, comment) {
  el.innerHTML = comment;
  el.textContent = comment;
}

function lookup(db, id) {
  return db.query(`SELECT * FROM orders WHERE id = ${id}`);
}

const agent = { rejectUnauthorized: false };
const digest = crypto.createHash("md5").update("x").digest("hex");
const strong = crypto.createHash("sha256").update("x").digest("hex");
module.exports = { ping, render, lookup, agent, digest, strong };
