/**
 * Offline supply-chain reference data.
 *
 * This ships in the binary so that typosquat and malicious-package detection
 * works with no network at all. It is a seed list, not a complete registry
 * mirror, and the product says so: an air-gapped install refreshes it from a
 * signed offline advisory bundle rather than from a live API.
 *
 * The malicious list is restricted to names that were themselves published as
 * attacks -- typosquats and impersonations -- from public incident reporting.
 * Legitimate packages that suffered a single compromised release are handled
 * separately, because flagging a package by name when only one version was bad
 * produces exactly the kind of false positive that gets a scanner muted.
 */

/**
 * High-download packages used as the comparison set for typosquat detection.
 * Chosen for download volume, since squatters target what people type most.
 */
export const POPULAR_PACKAGES: Record<string, Set<string>> = {
  npm: new Set([
    "react", "react-dom", "next", "vue", "svelte", "angular", "express", "fastify", "koa",
    "lodash", "underscore", "axios", "node-fetch", "got", "request", "superagent",
    "moment", "dayjs", "date-fns", "luxon", "chalk", "colors", "commander", "yargs",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "vitest", "cypress",
    "webpack", "vite", "rollup", "esbuild", "babel", "parcel", "gulp", "grunt",
    "dotenv", "cross-env", "nodemon", "pm2", "concurrently", "rimraf", "mkdirp", "glob",
    "mongoose", "sequelize", "prisma", "knex", "typeorm", "pg", "mysql", "mysql2",
    "sqlite3", "better-sqlite3", "redis", "ioredis", "mongodb",
    "jsonwebtoken", "bcrypt", "bcryptjs", "argon2", "passport", "helmet", "cors",
    "socket.io", "ws", "graphql", "apollo-server", "zod", "yup", "joi", "ajv",
    "uuid", "nanoid", "classnames", "clsx", "tailwindcss", "postcss", "autoprefixer",
    "puppeteer", "playwright", "cheerio", "jsdom", "sharp", "multer", "formidable",
    "winston", "pino", "morgan", "debug", "semver", "minimist", "inquirer", "ora",
    "openai", "anthropic", "langchain", "ollama", "stripe", "twilio", "nodemailer",
    "aws-sdk", "googleapis", "firebase", "supabase", "octokit", "simple-git",
    "body-parser", "cookie-parser", "express-session", "compression", "serve-static",
    "d3", "three", "chart.js", "lodash-es", "immer", "zustand", "redux", "recoil",
  ]),
  PyPI: new Set([
    "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "scikit-learn",
    "django", "flask", "fastapi", "starlette", "uvicorn", "gunicorn", "celery",
    "sqlalchemy", "alembic", "psycopg2", "pymongo", "redis", "boto3", "botocore",
    "pytest", "tox", "black", "flake8", "mypy", "ruff", "isort", "pylint",
    "pillow", "opencv-python", "beautifulsoup4", "lxml", "selenium", "scrapy",
    "click", "typer", "rich", "colorama", "tqdm", "pyyaml", "toml", "python-dotenv",
    "cryptography", "pyjwt", "passlib", "bcrypt", "paramiko", "certifi",
    "torch", "tensorflow", "transformers", "openai", "anthropic", "langchain",
    "jinja2", "markupsafe", "werkzeug", "itsdangerous", "attrs", "pydantic",
    "setuptools", "wheel", "pip", "virtualenv", "poetry", "six", "dateutil",
    "python-dateutil", "pytz", "httpx", "aiohttp", "websockets", "protobuf",
  ]),
  "crates.io": new Set([
    "serde", "serde_json", "tokio", "reqwest", "clap", "anyhow", "thiserror",
    "rand", "regex", "chrono", "uuid", "log", "env_logger", "tracing", "axum",
    "actix-web", "hyper", "sqlx", "diesel", "rayon", "itertools", "once_cell",
  ]),
  Go: new Set([]),
  RubyGems: new Set([
    "rails", "rack", "puma", "sinatra", "devise", "rspec", "rubocop", "nokogiri",
    "sidekiq", "pg", "mysql2", "redis", "jwt", "bcrypt", "faraday", "httparty",
  ]),
  Packagist: new Set([
    "symfony/console", "laravel/framework", "guzzlehttp/guzzle", "monolog/monolog",
    "phpunit/phpunit", "doctrine/orm", "twig/twig", "psr/log",
  ]),
  Maven: new Set([]),
};

/**
 * Packages published as attacks. Sources are the npm security advisories for the
 * 2017 typosquatting campaign, and public PyPI removal notices from 2017-2022.
 * Keep this list conservative: a false "this package is malicious" is a serious
 * accusation and destroys trust in every other finding.
 */
export const KNOWN_MALICIOUS: Record<string, Map<string, string>> = {
  npm: new Map([
    ["crossenv", "Typosquat of cross-env published in the 2017 npm typosquatting campaign; exfiltrated environment variables at install time."],
    ["cross-env.js", "Typosquat of cross-env from the same 2017 campaign."],
    ["mongose", "Typosquat of mongoose from the 2017 npm typosquatting campaign."],
    ["mysqljs", "Typosquat of mysql from the 2017 npm typosquatting campaign."],
    ["nodemailer.js", "Typosquat of nodemailer from the 2017 npm typosquatting campaign."],
    ["nodemailer-js", "Typosquat of nodemailer from the 2017 npm typosquatting campaign."],
    ["jquery.js", "Typosquat of jquery from the 2017 npm typosquatting campaign."],
    ["d3.js", "Typosquat of d3 from the 2017 npm typosquatting campaign."],
    ["babelcli", "Typosquat of babel-cli from the 2017 npm typosquatting campaign."],
    ["gruntcli", "Typosquat of grunt-cli from the 2017 npm typosquatting campaign."],
    ["ffmepg", "Typosquat of ffmpeg from the 2017 npm typosquatting campaign."],
    ["nodeffmpeg", "Typosquat from the 2017 npm typosquatting campaign."],
    ["nodefabric", "Typosquat of fabric from the 2017 npm typosquatting campaign."],
    ["node-fabric", "Typosquat of fabric from the 2017 npm typosquatting campaign."],
    ["fabric-js", "Typosquat of fabric from the 2017 npm typosquatting campaign."],
    ["nodesass", "Typosquat of node-sass from the 2017 npm typosquatting campaign."],
    ["nodesqlite", "Typosquat of node-sqlite from the 2017 npm typosquatting campaign."],
    ["sqlite.js", "Typosquat of sqlite from the 2017 npm typosquatting campaign."],
    ["sqliter", "Typosquat of sqlite from the 2017 npm typosquatting campaign."],
    ["mssql.js", "Typosquat of mssql from the 2017 npm typosquatting campaign."],
    ["mssql-node", "Typosquat of mssql from the 2017 npm typosquatting campaign."],
    ["mongodb.js", "Typosquat of mongodb from the 2017 npm typosquatting campaign."],
    ["opencv.js", "Typosquat of opencv from the 2017 npm typosquatting campaign."],
    ["openssl.js", "Typosquat of openssl from the 2017 npm typosquatting campaign."],
    ["http-proxy.js", "Typosquat of http-proxy from the 2017 npm typosquatting campaign."],
    ["proxy.js", "Typosquat of proxy from the 2017 npm typosquatting campaign."],
    ["noderequest", "Typosquat of request from the 2017 npm typosquatting campaign."],
    ["nodecaffe", "Typosquat from the 2017 npm typosquatting campaign."],
    ["shadowsock", "Typosquat of shadowsocks from the 2017 npm typosquatting campaign."],
  ]),
  PyPI: new Map([
    ["colourama", "Typosquat of colorama removed from PyPI in 2018; shipped a cryptocurrency clipboard hijacker."],
    ["jeIlyfish", "Typosquat of jellyfish using a capital I in place of the first l; removed from PyPI in 2019 for credential theft."],
    ["python3-dateutil", "Impersonation of python-dateutil removed from PyPI in 2019; imported the jeIlyfish payload."],
    ["urlib3", "Typosquat of urllib3 removed from PyPI in the 2017 removal batch."],
    ["urllib", "Impersonation of the standard library module removed from PyPI in the 2017 removal batch."],
    ["setup-tools", "Typosquat of setuptools removed from PyPI in the 2017 removal batch."],
    ["acqusition", "Typosquat of acquisition removed from PyPI in the 2017 removal batch."],
    ["apidev-coop", "Typosquat removed from PyPI in the 2017 removal batch."],
    ["bzip", "Typosquat of bz2file removed from PyPI in the 2017 removal batch."],
    ["crypt", "Impersonation of the standard library module removed from PyPI in the 2017 removal batch."],
    ["django-server", "Typosquat removed from PyPI in the 2017 removal batch."],
    ["telnet", "Impersonation of telnetlib removed from PyPI in the 2017 removal batch."],
    ["ctx", "Hijacked in 2022 to exfiltrate environment variables including AWS credentials."],
  ]),
  "crates.io": new Map([
    ["rustdecimal", "Typosquat of rust_decimal removed from crates.io in 2022; executed a payload in CI."],
  ]),
  Go: new Map(),
  RubyGems: new Map(),
  Packagist: new Map(),
  Maven: new Map(),
};

/**
 * Packages with a documented compromised release. Reported as "check your
 * version", never as "this package is malicious", because the current versions
 * are legitimate and widely used.
 */
export const COMPROMISED_RELEASES: Record<string, { versions: string[]; note: string }> = {
  "event-stream": {
    versions: ["3.3.6"],
    note: "The 3.3.6 release pulled in flatmap-stream, which targeted a specific cryptocurrency wallet (2018).",
  },
  "ua-parser-js": {
    versions: ["0.7.29", "0.8.0", "1.0.0"],
    note: "Three releases published from a hijacked maintainer account in October 2021 installed a cryptominer and a password stealer.",
  },
  coa: {
    versions: ["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"],
    note: "Releases published from a hijacked account in November 2021.",
  },
  rc: {
    versions: ["1.2.9", "1.3.9", "2.3.9"],
    note: "Releases published from a hijacked account in November 2021.",
  },
  "node-ipc": {
    versions: ["10.1.1", "10.1.2", "9.2.2"],
    note: "Protestware releases in March 2022 that overwrote files on machines geolocated to certain countries.",
  },
};

/** Install-script shapes that fetch and execute remote code. */
export const RISKY_INSTALL_PATTERNS: RegExp[] = [
  /curl[^\n|;]*\|\s*(?:ba|z|k|)sh/i,
  /wget[^\n|;]*\|\s*(?:ba|z|k|)sh/i,
  /curl[^\n]*-o[^\n]*&&[^\n]*(?:chmod|sh|bash)/i,
  /iwr[^\n]*\|\s*iex/i,
  /powershell[^\n]*-enc(?:odedcommand)?\s/i,
  /python\s+-c\s+["'][^"']*urlopen/i,
  /node\s+-e\s+["'][^"']*(?:http|fetch)/i,
  /eval\s*\(\s*\$\(/,
  /base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|)sh/i,
];
