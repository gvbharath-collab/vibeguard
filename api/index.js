// Vercel serverless entry. All /api/* requests are rewritten here (see vercel.json)
// and handled by the same request handler used by `npm start` in backend/.
module.exports = require('../backend/src/server.js');
