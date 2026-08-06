/**
 * Centralized Global Error Handling Middleware
 */

function errorHandler(err, req, res, next) {
  console.error(`[Error] ${err.message}`, err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    timestamp: new Date().toISOString()
  });
}

module.exports = errorHandler;
