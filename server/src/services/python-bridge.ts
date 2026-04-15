import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Python Bridge — executes DEADDROP CLI commands from the API server.
 * Communicates with the Python engine via subprocess.
 */
export class PythonBridge {
  private pythonCmd: string;

  constructor(pythonCmd: string = 'deaddrop') {
    this.pythonCmd = pythonCmd;
  }

  async run(args: string): Promise<any> {
    try {
      const argList = args.split(' ').filter(Boolean);
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
}