---
name: write-wl
description: Write a worklog entry for the current session. Creates or appends to .claude/worklog/YYYY-MM-DD.md with a summary of what was done, files touched, decisions made, and next steps.
argument-hint: [optional title]
user-invocable: true
allowed-tools: Read, Glob, Grep, Bash, Write, Edit
---

# Write Worklog Entry

Generate a worklog entry for today's session and save it to `.claude/worklog/`.

## Instructions

When invoked with `/write-wl [optional title]`:

1. **Determine the date**: Use today's date in `YYYY-MM-DD` format for the filename.

2. **Review what was done this session**: Look at:
   - Recent git changes: `git diff --stat HEAD~5` and `git log --oneline -10`
   - Files modified in this conversation
   - Decisions made during the session
   - Issues encountered and how they were resolved

3. **Check for existing worklog**: Read `.claude/worklog/YYYY-MM-DD.md` if it exists. If it does, append a new session section (## Session N) rather than overwriting.

4. **Write the entry** using this format:

```markdown
# YYYY-MM-DD — [Title from $ARGUMENTS or infer from work done]

## What was done
- [Bullet points of completed work]

## Files touched

### Created
- `path/to/file` — short description

### Modified
- `path/to/file` — what changed

### Deleted
- `path/to/file` — why removed

## Decisions made
1. **[Decision]** — [rationale]

## Issues encountered & resolved

| Issue | Root cause | Fix |
|-------|-----------|-----|
| [problem] | [cause] | [solution] |

## Current state
- [What's working, what's not, test status]

## Next steps
1. [What should be done next]
```

5. **Update brain.md** if any important decisions were made during the session. Add them to the Locked Decisions table or Known Gotchas section in `.claude/brain.md`.

6. **Confirm** the worklog was written and show the user a brief summary of what was logged.

## Rules
- Be thorough but concise — facts over narrative
- Always include the "Files touched" section with Created/Modified/Deleted subsections
- Only list files that were actually changed, not files that were just read
- If no decisions were made, omit that section
- If no issues were encountered, omit that section
- The title should be descriptive (e.g., "Cloud DB Testing", "Rule Engine Rewrite", not "Session 3")
