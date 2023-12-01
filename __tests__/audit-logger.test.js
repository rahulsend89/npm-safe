const { AuditLogger, getInstance } = require('../lib/audit-logger');
const fs = require('fs');
const path = require('path');

jest.mock('fs');

describe('AuditLogger', () => {
  let auditLogger;
  let mockStream;
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    mockStream = {
      write: jest.fn(),
      end: jest.fn(),
      on: jest.fn()
    };
    
    fs.createWriteStream.mockReturnValue(mockStream);
    fs.readFileSync.mockReturnValue('');
    
    jest.useFakeTimers();
  });
  
  afterEach(() => {
    if (auditLogger) {
      clearInterval(auditLogger.flushTimer);
      auditLogger = null;
    }
    jest.useRealTimers();
  });
  
  describe('constructor', () => {
    test('should create audit logger with default path', () => {
      auditLogger = new AuditLogger();
      
      expect(auditLogger.logPath).toBe('firewall-audit.jsonl');
      expect(auditLogger.buffer).toEqual([]);
      expect(fs.createWriteStream).toHaveBeenCalledWith('firewall-audit.jsonl', { flags: 'a' });
    });
    
    test('should create audit logger with custom path', () => {
      auditLogger = new AuditLogger('/custom/path.jsonl');
      
      expect(auditLogger.logPath).toBe('/custom/path.jsonl');
    });
    
    test('should handle stream creation error', () => {
      fs.createWriteStream.mockImplementation(() => {
        throw new Error('Cannot create stream');
      });
      
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      auditLogger = new AuditLogger();
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      expect(auditLogger.stream).toBeNull();
      
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('log', () => {
    beforeEach(() => {
      auditLogger = new AuditLogger();
    });
    
    test('should log event to buffer', () => {
      const event = {
        type: 'FILESYSTEM',
        operation: 'READ',
        target: '/etc/passwd',
        allowed: true, // Allowed events stay in buffer
        reason: 'exception',
        severity: 'info'
      };
      
      auditLogger.log(event);
      
      expect(auditLogger.buffer.length).toBe(1);
      expect(auditLogger.buffer[0]).toMatchObject({
        type: 'FILESYSTEM',
        operation: 'READ',
        target: '/etc/passwd',
        allowed: true,
        reason: 'exception',
        severity: 'info'
      });
    });
    
    test('should include stack trace for blocked critical events', () => {
      const event = {
        type: 'FILESYSTEM',
        operation: 'WRITE',
        target: '/tmp/evil.sh',
        allowed: false,
        reason: 'blocked',
        severity: 'critical'
      };
      
      auditLogger.log(event);
      
      // Critical events are flushed immediately, check what was written
      expect(mockStream.write).toHaveBeenCalled();
      const written = mockStream.write.mock.calls[0][0];
      const entry = JSON.parse(written.trim());
      
      expect(entry.stackTrace).toBeDefined();
      expect(Array.isArray(entry.stackTrace)).toBe(true);
    });
    
    test('should not include stack trace for allowed events', () => {
      const event = {
        type: 'FILESYSTEM',
        operation: 'READ',
        target: '/tmp/safe.txt',
        allowed: true,
        reason: 'allowed',
        severity: 'info'
      };
      
      auditLogger.log(event);
      
      expect(auditLogger.buffer[0].stackTrace).toBeUndefined();
    });
    
    test('should flush immediately for critical events', () => {
      const event = {
        type: 'FILESYSTEM',
        operation: 'WRITE',
        target: '/tmp/evil.sh',
        allowed: false,
        reason: 'blocked',
        severity: 'critical'
      };
      
      auditLogger.log(event);
      
      expect(mockStream.write).toHaveBeenCalled();
      expect(auditLogger.buffer.length).toBe(0);
    });
    
    test('should flush when buffer is full', () => {
      for (let i = 0; i < 101; i++) {
        auditLogger.log({
          type: 'TEST',
          operation: 'TEST',
          target: `test${i}`,
          allowed: true,
          reason: 'test'
        });
      }
      
      expect(mockStream.write).toHaveBeenCalled();
    });
  });
  
  describe('flush', () => {
    beforeEach(() => {
      auditLogger = new AuditLogger();
    });
    
    test('should write buffer to stream', () => {
      auditLogger.buffer = [
        { type: 'TEST', operation: 'TEST', target: 'test1' },
        { type: 'TEST', operation: 'TEST', target: 'test2' }
      ];
      
      auditLogger.flush();
      
      expect(mockStream.write).toHaveBeenCalled();
      expect(auditLogger.buffer.length).toBe(0);
    });
    
    test('should do nothing if buffer is empty', () => {
      auditLogger.flush();
      
      expect(mockStream.write).not.toHaveBeenCalled();
    });
    
    test('should handle write errors', () => {
      mockStream.write.mockImplementation(() => {
        throw new Error('Write error');
      });
      
      auditLogger.buffer = [{ type: 'TEST' }];
      
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      auditLogger.flush();
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('close', () => {
    beforeEach(() => {
      auditLogger = new AuditLogger();
    });
    
    test('should flush buffer and end stream', () => {
      auditLogger.buffer = [{ type: 'TEST' }];
      
      auditLogger.close();
      
      expect(mockStream.write).toHaveBeenCalled();
      expect(mockStream.end).toHaveBeenCalled();
      expect(auditLogger.stream).toBeNull();
    });
  });
  
  describe('queryRecent', () => {
    beforeEach(() => {
      auditLogger = new AuditLogger();
    });
    
    test('should query recent log entries', () => {
      const mockLogs = [
        JSON.stringify({ type: 'FILESYSTEM', allowed: false }),
        JSON.stringify({ type: 'NETWORK', allowed: true }),
        JSON.stringify({ type: 'COMMAND', allowed: false })
      ].join('\n');
      
      fs.readFileSync.mockReturnValue(mockLogs);
      
      const results = auditLogger.queryRecent(10);
      
      expect(results.length).toBe(3);
    });
    
    test('should filter by type', () => {
      const mockLogs = [
        JSON.stringify({ type: 'FILESYSTEM', allowed: false }),
        JSON.stringify({ type: 'NETWORK', allowed: true }),
        JSON.stringify({ type: 'FILESYSTEM', allowed: false })
      ].join('\n');
      
      fs.readFileSync.mockReturnValue(mockLogs);
      
      const results = auditLogger.queryRecent(10, { type: 'FILESYSTEM' });
      
      expect(results.length).toBe(2);
      expect(results.every(r => r.type === 'FILESYSTEM')).toBe(true);
    });
    
    test('should filter by allowed status', () => {
      const mockLogs = [
        JSON.stringify({ type: 'FILESYSTEM', allowed: false }),
        JSON.stringify({ type: 'NETWORK', allowed: true }),
        JSON.stringify({ type: 'COMMAND', allowed: false })
      ].join('\n');
      
      fs.readFileSync.mockReturnValue(mockLogs);
      
      const results = auditLogger.queryRecent(10, { allowed: false });
      
      expect(results.length).toBe(2);
      expect(results.every(r => !r.allowed)).toBe(true);
    });
  });
  
  describe('getStats', () => {
    beforeEach(() => {
      auditLogger = new AuditLogger();
    });
    
    test('should return statistics', () => {
      const mockLogs = [
        JSON.stringify({ type: 'FILESYSTEM', allowed: false, severity: 'high', package: 'pkg1' }),
        JSON.stringify({ type: 'NETWORK', allowed: true, severity: 'info', package: 'pkg2' }),
        JSON.stringify({ type: 'FILESYSTEM', allowed: false, severity: 'critical', package: 'pkg1' })
      ].join('\n');
      
      fs.readFileSync.mockReturnValue(mockLogs);
      
      const stats = auditLogger.getStats();
      
      expect(stats.total).toBe(3);
      expect(stats.blocked).toBe(2);
      expect(stats.allowed).toBe(1);
      expect(stats.byType.FILESYSTEM).toBe(2);
      expect(stats.byType.NETWORK).toBe(1);
    });
  });
  
  describe('getInstance', () => {
    test('should return singleton instance', () => {
      const instance1 = getInstance();
      const instance2 = getInstance();
      
      expect(instance1).toBe(instance2);
    });
  });
});
