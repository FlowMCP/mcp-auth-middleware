import { jest } from '@jest/globals'
import { Logger } from '../../../src/helpers/Logger.mjs'

describe( 'Logger', () => {
    let consoleSpy

    beforeEach( () => {
        consoleSpy = {
            log: jest.spyOn( console, 'log' ).mockImplementation(),
            warn: jest.spyOn( console, 'warn' ).mockImplementation(),
            error: jest.spyOn( console, 'error' ).mockImplementation()
        }
    } )

    afterEach( () => {
        consoleSpy.log.mockRestore()
        consoleSpy.warn.mockRestore()
        consoleSpy.error.mockRestore()
    } )

    describe( 'log', () => {
        
        test( 'logs info message when not silent', () => {
            Logger.log( { silent: false, message: 'Test message', level: 'info' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Test message' )
        } )
        
        
        test( 'logs warning message with emoji when not silent', () => {
            Logger.log( { silent: false, message: 'Warning message', level: 'warn' } )
            
            expect( consoleSpy.warn ).toHaveBeenCalledWith( '⚠️ Warning message' )
        } )
        
        
        test( 'logs error message with emoji when not silent', () => {
            Logger.log( { silent: false, message: 'Error message', level: 'error' } )
            
            expect( consoleSpy.error ).toHaveBeenCalledWith( '❌Error message' )
        } )
        
        
        test( 'logs success message with emoji when not silent', () => {
            Logger.log( { silent: false, message: 'Success message', level: 'success' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( '✅Success message' )
        } )
        
        
        test( 'does not log when silent is true', () => {
            Logger.log( { silent: true, message: 'Silent message', level: 'info' } )
            
            expect( consoleSpy.log ).not.toHaveBeenCalled()
            expect( consoleSpy.warn ).not.toHaveBeenCalled()
            expect( consoleSpy.error ).not.toHaveBeenCalled()
        } )
        
        
        test( 'defaults to info level when level not specified', () => {
            Logger.log( { silent: false, message: 'Default level message' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Default level message' )
        } )
        
        
        test( 'defaults to silent false when silent not specified', () => {
            Logger.log( { message: 'Default silent message' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Default silent message' )
        } )
        
        
        test( 'handles unknown log level gracefully', () => {
            Logger.log( { silent: false, message: 'Unknown level', level: 'unknown' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Unknown level' )
        } )
        
    } )

    describe( 'info', () => {
        
        test( 'logs info message when not silent', () => {
            Logger.info( { silent: false, message: 'Info message' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Info message' )
        } )
        
        
        test( 'does not log when silent is true', () => {
            Logger.info( { silent: true, message: 'Silent info' } )
            
            expect( consoleSpy.log ).not.toHaveBeenCalled()
        } )
        
        
        test( 'defaults to silent false', () => {
            Logger.info( { message: 'Default info' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( 'Default info' )
        } )
        
    } )

    describe( 'warn', () => {
        
        test( 'logs warning message with emoji when not silent', () => {
            Logger.warn( { silent: false, message: 'Warning message' } )
            
            expect( consoleSpy.warn ).toHaveBeenCalledWith( '⚠️ Warning message' )
        } )
        
        
        test( 'does not log when silent is true', () => {
            Logger.warn( { silent: true, message: 'Silent warning' } )
            
            expect( consoleSpy.warn ).not.toHaveBeenCalled()
        } )
        
        
        test( 'defaults to silent false', () => {
            Logger.warn( { message: 'Default warning' } )
            
            expect( consoleSpy.warn ).toHaveBeenCalledWith( '⚠️ Default warning' )
        } )
        
    } )

    describe( 'error', () => {
        
        test( 'logs error message with emoji when not silent', () => {
            Logger.error( { silent: false, message: 'Error message' } )
            
            expect( consoleSpy.error ).toHaveBeenCalledWith( '❌Error message' )
        } )
        
        
        test( 'does not log when silent is true', () => {
            Logger.error( { silent: true, message: 'Silent error' } )
            
            expect( consoleSpy.error ).not.toHaveBeenCalled()
        } )
        
        
        test( 'defaults to silent false', () => {
            Logger.error( { message: 'Default error' } )
            
            expect( consoleSpy.error ).toHaveBeenCalledWith( '❌Default error' )
        } )
        
    } )

    describe( 'success', () => {
        
        test( 'logs success message with emoji when not silent', () => {
            Logger.success( { silent: false, message: 'Success message' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( '✅Success message' )
        } )
        
        
        test( 'does not log when silent is true', () => {
            Logger.success( { silent: true, message: 'Silent success' } )
            
            expect( consoleSpy.log ).not.toHaveBeenCalled()
        } )
        
        
        test( 'defaults to silent false', () => {
            Logger.success( { message: 'Default success' } )
            
            expect( consoleSpy.log ).toHaveBeenCalledWith( '✅Default success' )
        } )
        
    } )
} )