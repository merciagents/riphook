import path from "node:path";

type ValidationResult = {
  isSafe: boolean;
  severity: "block" | "warn" | "ok";
  reason: string;
};

const DANGEROUS_PATTERNS: Array<[RegExp, string]> = [
  [/rm\s+-rf\s+\//i, "Recursive delete from root"],
  [/rm\s+-rf\s+~/i, "Recursive delete from home"],
  [/rm\s+-rf\s+\*/i, "Recursive delete wildcard"],
  [/rm\s+-rf\b/i, "Recursive delete"],
  [/find\b.*-delete\b/i, "Find delete"],
  [/git\s+reset\s+--hard\b/i, "Git hard reset"],
  [/git\s+clean\s+-[^\n]*f\b/i, "Git clean force"],
  [/git\s+push\s+--force\b/i, "Git force push"],
  [/git\s+branch\s+-D\b/i, "Git branch delete"],
  [/\bsudo\b/i, "Sudo command"],
  [/>\s*\/dev\/sd/i, "Write to block device"],
  [/dd\s+if=.*of=\/dev\//i, "Direct disk write"],
  [/mkfs\./i, "Filesystem format"],
  [/chmod\s+777\s+\//i, "Overly permissive root chmod"],
  [/curl.*\|\s*(?:ba)?sh/i, "Pipe URL to shell"],
  [/wget.*\|\s*(?:ba)?sh/i, "Pipe URL to shell"],
  [/:\(\)\s*\{\s*:\|:&\s*\}/i, "Fork bomb"],
  [/>\s*\/etc\/passwd/i, "Overwrite passwd"],
  [/>\s*\/etc\/shadow/i, "Overwrite shadow"],
  [/cat\s+\/etc\/shadow/i, "Read shadow file"],
  [/base64\s+-d.*\|\s*(?:ba)?sh/i, "Decode and execute"],
  [/python.*-c.*exec\s*\(/i, "Python exec injection"],
  [/eval\s*\$\(/i, "Eval command substitution"],
  [/\$\(.*curl.*\)/i, "Command substitution with curl"],
  [/\b(shutdown|reboot)\b/i, "Shutdown or reboot"],
  [/\b(kill\s+-9|pkill|killall)\b/i, "Force kill process"],
  [/\b(iptables|ufw|firewall-cmd)\b/i, "Firewall modification"],
  [/\bdrop\s+(database|table)\b/i, "SQL drop"],
  [/\btruncate\s+table\b/i, "SQL truncate"],
  [/\bdelete\s+from\s+\S+\b(?!.*\bwhere\b)/i, "SQL delete without where"],
];

const SENSITIVE_PATTERNS: Array<[RegExp, string]> = [
  [/\.env/i, "Environment file access"],
  [/\.ssh\//i, "SSH directory access"],
  [/id_rsa/i, "SSH private key"],
  [/\.aws\/credentials/i, "AWS credentials"],
  [/\.git\/config/i, "Git config (may contain tokens)"],
  [/\.npmrc/i, "NPM config (may contain tokens)"],
  [/\.pypirc/i, "PyPI config (may contain tokens)"],
  [/credentials\.json/i, "Credentials file"],
  [/secrets\.json/i, "Secrets file"],
  [/\.kube\/config/i, "Kubernetes config"],
];

const PROTECTED_WRITE_PATHS = [
  "/etc/",
  "/bin/",
  "/sbin/",
  "/usr/bin/",
  "/usr/sbin/",
  "/boot/",
  "/sys/",
  "/proc/",
  "/dev/",
];

const PROTECTED_READ_FILES = ["/etc/shadow", "/etc/passwd", "/etc/sudoers"];

function validateCommand(command = ""): ValidationResult {
  if (!command) return { isSafe: true, severity: "ok", reason: "" };

  for (const [pattern, reason] of DANGEROUS_PATTERNS) {
    if (pattern.test(command)) {
      return { isSafe: false, severity: "block", reason };
    }
  }

  for (const [pattern, reason] of SENSITIVE_PATTERNS) {
    if (pattern.test(command)) {
      return { isSafe: true, severity: "warn", reason };
    }
  }

  return { isSafe: true, severity: "ok", reason: "" };
}

function validateFileWrite(filePath = ""): ValidationResult {
  if (!filePath) return { isSafe: true, severity: "ok", reason: "" };

  const normalized = path.normalize(filePath);
  for (const protectedPath of PROTECTED_WRITE_PATHS) {
    if (normalized.startsWith(protectedPath)) {
      return {
        isSafe: false,
        severity: "block",
        reason: `Write to protected path: ${protectedPath}`,
      };
    }
  }

  for (const [pattern, reason] of SENSITIVE_PATTERNS) {
    if (pattern.test(normalized)) {
      return { isSafe: true, severity: "warn", reason };
    }
  }

  return { isSafe: true, severity: "ok", reason: "" };
}

function validateFileRead(filePath = ""): ValidationResult {
  if (!filePath) return { isSafe: true, severity: "ok", reason: "" };

  const normalized = path.normalize(filePath);
  for (const protectedFile of PROTECTED_READ_FILES) {
    if (normalized === protectedFile) {
      return {
        isSafe: false,
        severity: "block",
        reason: `Read of protected system file: ${protectedFile}`,
      };
    }
  }

  for (const protectedPath of PROTECTED_WRITE_PATHS) {
    if (normalized.startsWith(protectedPath)) {
      return {
        isSafe: false,
        severity: "block",
        reason: `Read from protected system path: ${protectedPath}`,
      };
    }
  }

  for (const [pattern, reason] of SENSITIVE_PATTERNS) {
    if (pattern.test(normalized)) {
      return { isSafe: true, severity: "warn", reason };
    }
  }

  return { isSafe: true, severity: "ok", reason: "" };
}

function validateToolInput(
  toolName = "",
  toolInput: Record<string, unknown> = {},
): ValidationResult {
  if (!toolInput || typeof toolInput !== "object") {
    return { isSafe: true, severity: "ok", reason: "" };
  }

  if (["Bash", "run_terminal_cmd", "Shell"].includes(toolName)) {
    return validateCommand(String(toolInput.command ?? ""));
  }

  if (["Write", "Edit", "search_replace"].includes(toolName)) {
    return validateFileWrite(String(toolInput.file_path ?? ""));
  }

  if (["Read", "read_file"].includes(toolName)) {
    return validateFileRead(
      String(toolInput.file_path ?? toolInput.target_file ?? ""),
    );
  }

  if (toolName === "Task") {
    const prompt = String(toolInput.prompt ?? "");
    for (const [pattern, reason] of DANGEROUS_PATTERNS) {
      if (pattern.test(prompt)) {
        return {
          isSafe: true,
          severity: "warn",
          reason: `Prompt contains pattern: ${reason}`,
        };
      }
    }
  }

  if (toolName.startsWith("mcp_") || toolName.toLowerCase().includes("mcp")) {
    for (const [key, value] of Object.entries(toolInput)) {
      if (typeof value !== "string") continue;
      for (const [pattern, reason] of DANGEROUS_PATTERNS) {
        if (pattern.test(value)) {
          return {
            isSafe: false,
            severity: "block",
            reason: `Dangerous pattern in ${key}: ${reason}`,
          };
        }
      }
    }
  }

  return { isSafe: true, severity: "ok", reason: "" };
}

export type { ValidationResult };
export {
  DANGEROUS_PATTERNS,
  SENSITIVE_PATTERNS,
  PROTECTED_READ_FILES,
  PROTECTED_WRITE_PATHS,
  validateCommand,
  validateFileRead,
  validateFileWrite,
  validateToolInput,
};
