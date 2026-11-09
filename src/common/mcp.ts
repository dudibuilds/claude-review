/**
 * Constants shared by both MCP servers (xsearch, xreview).
 */

/**
 * Tool `_meta` that makes Claude Code load the tool up front instead of deferring it behind its
 * built-in ToolSearch tool (SPEC "Tool loading (no deferral)"). Every xsearch and xreview tool is
 * registered with it.
 */
export const ALWAYS_LOAD_META = { "anthropic/alwaysLoad": true } as const;
