import {
  appendTrace,
  computeRangePositions,
  createTrace,
  tryReadFile,
} from "../core/traceStore.js";
import { appendEditedFilePath } from "../core/editedFilesCache.js";

function handleAfterFileEdit(input: Record<string, unknown>): void {
  const filePath = input.file_path as string | undefined;
  if (!filePath) return;

  appendEditedFilePath(filePath);
  const edits = (input.edits as Array<Record<string, unknown>>) ?? [];
  const fileContent = tryReadFile(filePath);
  const rangePositions = computeRangePositions(edits, fileContent);

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath,
      model: input.model as string | undefined,
      rangePositions,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        conversation_id: input.conversation_id,
        generation_id: input.generation_id,
      },
    }),
  );
}

function handleAfterTabFileEdit(input: Record<string, unknown>): void {
  const filePath = input.file_path as string | undefined;
  if (!filePath) return;

  appendEditedFilePath(filePath);
  const edits = (input.edits as Array<Record<string, unknown>>) ?? [];
  const rangePositions = computeRangePositions(edits);

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath,
      model: input.model as string | undefined,
      rangePositions,
      metadata: {
        conversation_id: input.conversation_id,
        generation_id: input.generation_id,
      },
    }),
  );
}

function handleAfterShellExecution(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".shell-history",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        conversation_id: input.conversation_id,
        generation_id: input.generation_id,
        command: input.command,
        duration_ms: input.duration,
      },
    }),
  );
}

function handleSessionStart(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".sessions",
      model: input.model as string | undefined,
      metadata: {
        event: "session_start",
        session_id: input.session_id,
        conversation_id: input.conversation_id,
        is_background_agent: input.is_background_agent,
        composer_mode: input.composer_mode,
        source: input.source,
      },
    }),
  );
}

function handleSessionEnd(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".sessions",
      model: input.model as string | undefined,
      metadata: {
        event: "session_end",
        session_id: input.session_id,
        conversation_id: input.conversation_id,
        reason: input.reason,
        duration_ms: input.duration_ms,
      },
    }),
  );
}

function handlePreToolUse(input: Record<string, unknown>): void {
  const toolName = (input.tool_name as string) ?? "";
  const toolInput = (input.tool_input as Record<string, unknown>) ?? {};

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".tool-usage",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "tool_use_attempt",
        tool_name: toolName,
        tool_use_id: input.tool_use_id,
        tool_input: toolInput,
        cwd: input.cwd,
        agent_message: input.agent_message,
      },
    }),
  );
}

function handlePostToolUse(input: Record<string, unknown>): void {
  const toolName = (input.tool_name as string) ?? "";
  const toolInput = (input.tool_input as Record<string, unknown>) ?? {};

  const isFileEdit = ["Write", "Edit", "search_replace", "Write"].includes(toolName);
  const isBash = ["Bash", "run_terminal_cmd", "Shell"].includes(toolName);
  const isRead = ["Read", "read_file"].includes(toolName);

  if (isFileEdit || isBash || isRead) {
    const filePath = isBash
      ? ".shell-history"
      : isFileEdit
        ? String(toolInput.file_path ?? ".unknown")
        : String(toolInput.file_path ?? ".file-reads");

    if (isFileEdit && filePath !== ".unknown") {
      appendEditedFilePath(filePath);
    }

    let rangePositions;
    if (isFileEdit && toolInput.new_string) {
      const edits = [
        {
          old_string: toolInput.old_string ?? "",
          new_string: toolInput.new_string ?? "",
        },
      ];
      if (toolInput.file_path) {
        const fileContent = tryReadFile(String(toolInput.file_path));
        rangePositions = computeRangePositions(edits, fileContent);
      }
    }

    appendTrace(
      createTrace({
        contributorType: "ai",
        filePath,
        model: input.model as string | undefined,
        rangePositions,
        transcript: input.transcript_path as string | undefined,
        metadata: {
          event: "tool_use_completed",
          tool_name: toolName,
          tool_use_id: input.tool_use_id,
          command: isBash ? toolInput.command : undefined,
          duration_ms: input.duration,
          cwd: input.cwd,
        },
      }),
    );
    return;
  }

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".tool-usage",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "tool_use_completed",
        tool_name: toolName,
        tool_use_id: input.tool_use_id,
        duration_ms: input.duration,
      },
    }),
  );
}

function handlePostToolUseFailure(input: Record<string, unknown>): void {
  const toolName = (input.tool_name as string) ?? "";

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".tool-failures",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "tool_use_failure",
        tool_name: toolName,
        tool_use_id: input.tool_use_id,
        error_message: input.error_message,
        failure_type: input.failure_type,
        duration_ms: input.duration,
        is_interrupt: input.is_interrupt,
        cwd: input.cwd,
      },
    }),
  );
}

function handleSubagentStart(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".subagents",
      model: input.model as string | undefined,
      metadata: {
        event: "subagent_start",
        subagent_type: input.subagent_type,
        prompt: input.prompt,
      },
    }),
  );
}

function handleSubagentStop(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".subagents",
      model: input.model as string | undefined,
      metadata: {
        event: "subagent_stop",
        subagent_type: input.subagent_type,
        status: input.status,
        duration_ms: input.duration,
        agent_transcript_path: input.agent_transcript_path,
      },
    }),
  );
}

function handleBeforeShellExecution(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".shell-history",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "shell_execution_attempt",
        command: input.command,
        cwd: input.cwd,
        timeout: input.timeout,
      },
    }),
  );
}

function handleBeforeMcpExecution(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".mcp-executions",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "mcp_execution_attempt",
        tool_name: input.tool_name,
        tool_input: input.tool_input,
        url: input.url,
        command: input.command,
      },
    }),
  );
}

function handleAfterMcpExecution(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".mcp-executions",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "mcp_execution_completed",
        tool_name: input.tool_name,
        tool_input: input.tool_input,
        duration_ms: input.duration,
      },
    }),
  );
}

function handleBeforeReadFile(input: Record<string, unknown>): void {
  const filePath = input.file_path as string | undefined;
  if (!filePath) return;

  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".file-reads",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "file_read_attempt",
        file_path: filePath,
        has_attachments: ((input.attachments as unknown[]) ?? []).length > 0,
        attachments: input.attachments ?? [],
      },
    }),
  );
}

function handleBeforeSubmitPrompt(input: Record<string, unknown>): void {
  const prompt = (input.prompt as string) ?? "";
  const promptLower = prompt.toLowerCase();
  const indicators = [
    "security finding",
    "security finding(s)",
    "semgrep scan",
    "vulnerability",
    "vulnerabilities",
    "review the findings",
    "address any security issues",
  ];
  const isSecurityFollowup = indicators.some((indicator) =>
    promptLower.includes(indicator),
  );

  const metadata: Record<string, unknown> = {
    event: "prompt_submission_attempt",
    prompt_length: prompt.length,
    has_attachments: ((input.attachments as unknown[]) ?? []).length > 0,
    attachment_count: ((input.attachments as unknown[]) ?? []).length,
  };

  if (isSecurityFollowup) {
    metadata.source = "hooks-project";
    metadata.source_hook = "stop";
  }

  appendTrace(
    createTrace({
      contributorType: isSecurityFollowup ? "ai" : "human",
      filePath: ".prompts",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata,
    }),
  );
}

function handleAfterAgentResponse(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".agent-responses",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "agent_response",
        text_length: String(input.text ?? "").length,
      },
    }),
  );
}

function handleAfterAgentThought(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".agent-thoughts",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "agent_thought",
        text_length: String(input.text ?? "").length,
        duration_ms: input.duration_ms,
      },
    }),
  );
}

function handlePreCompact(input: Record<string, unknown>): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".context-compactions",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "context_compaction",
        trigger: input.trigger,
        context_usage_percent: input.context_usage_percent,
        context_tokens: input.context_tokens,
        context_window_size: input.context_window_size,
        message_count: input.message_count,
        messages_to_compact: input.messages_to_compact,
        is_first_compaction: input.is_first_compaction,
      },
    }),
  );
}

export {
  handleAfterFileEdit,
  handleAfterTabFileEdit,
  handleAfterShellExecution,
  handleSessionStart,
  handleSessionEnd,
  handlePreToolUse,
  handlePostToolUse,
  handlePostToolUseFailure,
  handleSubagentStart,
  handleSubagentStop,
  handleBeforeShellExecution,
  handleBeforeMcpExecution,
  handleAfterMcpExecution,
  handleBeforeReadFile,
  handleBeforeSubmitPrompt,
  handleAfterAgentResponse,
  handleAfterAgentThought,
  handlePreCompact,
};
