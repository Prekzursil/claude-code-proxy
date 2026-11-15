const { Transform } = require('stream');

// Matches Anthropic API keys and bearer-style tokens so they never reach the console in clear text
const TOKEN_PATTERN = /\b(sk-ant-[A-Za-z0-9._-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{16,})/g;
// Control characters (excluding \t) that enable log forging / terminal escape attacks
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
// Object keys whose values are always sensitive
const SENSITIVE_KEY = /authorization|token|secret|api[-_]?key|password|cookie/i;

class Logger {
  static init(config) {
    this.config = config;
  }

  static getLogLevel() {
    const levels = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3, TRACE: 4 };
    return levels[this.config?.log_level] || 2;
  }

  /**
   * Make a value safe to write to a log: strips control characters, collapses
   * line breaks (log-forging defense) and redacts credential material.
   */
  static _clean(value, depth = 0) {
    if (typeof value === 'string') {
      return value
        .replace(CONTROL_CHARS, '')
        .replace(/[\r\n]+/g, ' ')
        .replace(TOKEN_PATTERN, (m) => (m.startsWith('Bearer') ? 'Bearer [REDACTED]' : '[REDACTED]'));
    }
    if (depth >= 3 || value === null || typeof value !== 'object') {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((v) => this._clean(v, depth + 1));
    }
    const cleaned = {};
    for (const [key, val] of Object.entries(value)) {
      cleaned[key] = SENSITIVE_KEY.test(key) && typeof val === 'string' && val.length > 0 ? '[REDACTED]' : this._clean(val, depth + 1);
    }
    return cleaned;
  }

  static debug(...args) {
    if (this.getLogLevel() >= 3) {
      console.log('DEBUG:', ...args.map((a) => this._clean(a)));
    }
  }

  static trace(...args) {
    if (this.getLogLevel() >= 4) {
      console.log('TRACE:', ...args.map((a) => this._clean(a)));
    }
  }

  static info(...args) {
    console.log('INFO:', ...args.map((a) => this._clean(a)));
  }

  static warn(...args) {
    console.warn('WARN:', ...args.map((a) => this._clean(a)));
  }

  static error(...args) {
    console.error('ERROR:', ...args.map((a) => this._clean(a)));
  }

  static createDebugStream(label = 'Stream chunk', textExtractor = null) {
    if (this.getLogLevel() < 3) {
      return new Transform({
        transform(chunk, encoding, callback) {
          callback(null, chunk);
        }
      });
    }

    let streamingText = '';
    let thinkingText = '';
    let hasStartedStreaming = false;
    let hasStartedResponse = false;
    const logLevel = this.getLogLevel();
    
    return new Transform({
      transform(chunk, encoding, callback) {
        try {
          const chunkStr = chunk.toString();
          
          if (logLevel >= 4) {
            Logger.trace(`${label} (${chunkStr.length} bytes): ${chunkStr}`);
          } else if (logLevel >= 3) {
            if (textExtractor) {
              const result = textExtractor(chunk);
              if (result?.text) {
                if (!hasStartedStreaming) {
                  Logger.debug(`${label} streaming started`);
                  hasStartedStreaming = true;
                }
                if (thinkingText && !hasStartedResponse) {
                  process.stdout.write('\n');
                  Logger.debug(`${label} switching from thinking to response`);
                  hasStartedResponse = true;
                }
                streamingText += result.text;
                process.stdout.write(result.text);
              }
              if (result?.thinking) {
                if (!hasStartedStreaming) {
                  Logger.debug(`${label} streaming started`);
                  hasStartedStreaming = true;
                }
                thinkingText += result.thinking;
                process.stdout.write(`\x1b[90m${result.thinking}\x1b[0m`);
              }
            } else {
              Logger.debug(`${label} (${chunkStr.length} bytes): ${chunkStr}`);
            }
          }
        } catch (error) {
          Logger.debug(`${label} (failed to decode):`, chunk);
        }
        callback(null, chunk);
      }
    });
  }

}

module.exports = Logger;