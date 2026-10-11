const rows = [];
module.exports = { run: (sql, params) => ({ changes: 1 }), all: (sql, params) => rows, get: (sql, params) => null };
