module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  collectCoverageFrom: [
    'common/src/**/*.js',
    'gateway/src/**/*.js',
    'analyzers/src/**/*.js',
  ],
  coverageThreshold: {
    global: {
      branches: 60,
      functions: 70,
      lines: 70,
    },
  },
  testTimeout: 15000,
};
