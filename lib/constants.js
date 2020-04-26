/* 
 * (C) 2018 TekMonks. All rights reserved.
 */

const path = require("path");
const rootdir = path.resolve(__dirname+"/../");

exports.ROOTDIR = rootdir;
exports.LIBDIR = path.normalize(rootdir+"/lib");
exports.CONFDIR = path.normalize(rootdir+"/conf");
exports.EXTDIR = path.normalize(rootdir+"/extensions");
exports.LOGDIR = path.normalize(rootdir+"/logs");
exports.LOGSCONF = rootdir+"/conf/log.json";
exports.CLUSTERCONF = rootdir+"/conf/cluster.json";
exports.FIREWALLCONF = rootdir+"/conf/socks5.json";

exports.CRYPTCONF = rootdir+"/conf/crypt.json";

exports.MAX_LOG = 1024;
exports.DEFAULT_CHECKS_DELAY = 500;

/* Encryption constants */
exports.CRPT_ALGO = "aes-256-ctr";
