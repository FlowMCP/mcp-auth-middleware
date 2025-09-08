/**
 * Centralized Logger for OAuth Middleware
 * 
 * Provides consistent logging across all OAuth middleware components
 * with support for silent mode and different log levels.
 */
class Logger {

    /**
     * Log a message with specified level and silent mode support
     * 
     * @param {Object} params - Logging parameters
     * @param {boolean} params.silent - Whether to suppress output
     * @param {string} params.message - Message to log
     * @param {string} params.level - Log level: info, warn, error, success
     */
    static log( { silent = false, message, level = 'info' } ) {
        if( silent ) {
            return
        }

        const prefixes = {
            info: '',
            warn: '⚠️ ',
            error: '❌',
            success: '✅'
        }

        const prefix = prefixes[level] || ''
        const logMessage = `${prefix}${message}`

        switch( level ) {
            case 'warn':
                console.warn( logMessage )
                break
            case 'error':
                console.error( logMessage )
                break
            default:
                console.log( logMessage )
                break
        }
    }


    /**
     * Helper method for info level logging
     * 
     * @param {Object} params - Logging parameters
     * @param {boolean} params.silent - Whether to suppress output
     * @param {string} params.message - Message to log
     */
    static info( { silent = false, message } ) {
        Logger.log( { silent, message, level: 'info' } )
    }


    /**
     * Helper method for warning level logging
     * 
     * @param {Object} params - Logging parameters
     * @param {boolean} params.silent - Whether to suppress output
     * @param {string} params.message - Message to log
     */
    static warn( { silent = false, message } ) {
        Logger.log( { silent, message, level: 'warn' } )
    }


    /**
     * Helper method for error level logging
     * 
     * @param {Object} params - Logging parameters
     * @param {boolean} params.silent - Whether to suppress output
     * @param {string} params.message - Message to log
     */
    static error( { silent = false, message } ) {
        Logger.log( { silent, message, level: 'error' } )
    }


    /**
     * Helper method for success level logging
     * 
     * @param {Object} params - Logging parameters
     * @param {boolean} params.silent - Whether to suppress output
     * @param {string} params.message - Message to log
     */
    static success( { silent = false, message } ) {
        Logger.log( { silent, message, level: 'success' } )
    }
}

export { Logger }