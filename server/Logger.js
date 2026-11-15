const { Transform } = require('stream');

// Matches Anthropic API keys and bearer-style tokens so they never reach the console in clear text
const TOKEN_PATTERN = /\b(sk-ant-[A-Za-z0-9._-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{16,})/g;
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
   * Redact and encode a string for safe logging:
   * - the JSON.stringify round-trip escapes `\r`, `\n` and all other control
   *   characters, so a crafted payload cannot forge log entries
   * - credential material is masked
   */
  static _sanitizeString(s) {
    return JSON.stringify(s).slice(1, -1).replace(TOKEN_PATTERN, '[REDACTED]');
  }

  /**
   * Make any value safe to write to a log. Strings and objects are JSON
   * encoded (control characters escaped), values under sensitive keys and
   * inline credential patterns are replaced with '[REDACTED]'.
   */
  static redact(value) {
    if (typeof value === 'string') {
      return this._sanitizeString(value);
    }
    if (value instanceof Error) {
      return this._sanitizeString(`${value.name}: ${value.message}`);
    }
    if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
      return `[${typeof value}]`;
    }
    try {
      return this._sanitizeString(JSON.stringify(value, (key, val) => (
        (SENSITIVE_KEY.test(key) && typeof val === 'string' && val.length > 0) ? '[REDACTED]' : val
      )));
    } catch {
      return '[unserializable]';
    }
  }

  static debug(...args) {
    if (this.getLogLevel() >= 3) {
      console.log('DEBUG:', ...args.map((a) => this.redact(a)));
    }
  }

  static trace(...args) {
    if (this.getLogLevel() >= 4) {
      console.log('TRACE:', ...args.map((a) => this.redact(a)));
    }
  }

  static info(...args) {
    console.log('INFO:', ...args.map((a) => this.redact(a)));
  }

  static warn(...args) {
    console.warn('WARN:', ...args.map((a) => this.redact(a)));
  }

  static error(...args) {
    console.error('ERROR:', ...args.map((a) => this.redact(a)));
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