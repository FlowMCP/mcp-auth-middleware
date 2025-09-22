export default {
    testEnvironment: 'node',
    roots: ['<rootDir>/tests/unit'],
    testMatch: ['**/*.test.mjs'],
    collectCoverageFrom: [
        'src/**/*.mjs'
    ],
    coverageDirectory: 'coverage',
    coverageReporters: ['text', 'lcov', 'html'],
    coverageThreshold: {
        global: {
            branches: 60,
            functions: 70,
            lines: 70,
            statements: 70
        }
    },
    verbose: true,
    maxWorkers: 1,
    forceExit: true,
    testTimeout: 30000
}