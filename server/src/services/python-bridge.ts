import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Python Bridge — executes DEADDROP CLI commands from the API server.
 * Communicates with the Python engine via subprocess.
 *
 * IMPORTANT: Arguments are passed as an array, not split from a string,
 * to correctly handle paths with spaces (e.g. /Users/main/Security Apps/...)
 */
export class PythonBridge {
  private pythonCmd: string;

  constructor(pythonCmd: string = 'deaddrop') {
    this.pythonCmd = pythonCmd;
  }

  /**
   * Run a DEADDROP CLI command.
   *
   * @param args - Command arguments as an array (e.g. ['case', 'create', '--name', 'My Case'])
   *               If a single string is passed, it is split respecting quoted segments.
   */
  async run(args: string | string[]): Promise<any> {
    const argList = Array.isArray(args)
      ? args
      : this.parseArgs(args);

    try {
      const { stdout } = await execFileAsync(this.pythonCmd, argList, {
        timeout: 300000, // 5 minutes
        maxBuffer: 50 * 1024 * 1024, // 50MB
      });

      try {
        return JSON.parse(stdout);
      } catch {
        return { raw: stdout };
      }
    } catch (error: any) {
      return {
        error: error.message,
        stderr: error.stderr?.toString() || '',
        code: error.code,
      };
    }
  }

  /**
   * Parse a command string into arguments, respecting quoted segments.
   * Handles: --flag "value with spaces" and --flag='value'
   */
  private parseArgs(cmd: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuote: string | null = null;

    for (let i = 0; i < cmd.length; i++) {
      const ch = cmd[i];

      if (inQuote) {
        if (ch === inQuote) {
          inQuote = null;
        } else {
          current += ch;
        }
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (ch === ' ' || ch === '\t') {
        if (current) {
          result.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }

    if (current) {
      result.push(current);
    }

    return result;
  }
}