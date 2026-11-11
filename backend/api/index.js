// Vercel serverless entry for the backend project (Root Directory = backend).
// All /api/* requests are rewritten here (see backend/vercel.json) and handled
// by the same request handler used by `npm start`.
module.exports = require('../src/server.js');
