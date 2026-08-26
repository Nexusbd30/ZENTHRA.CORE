# BlackNode Threat Model

BlackNode assumes every input can be hostile.

Threat categories:

- Prompt injection
- Malicious documents
- Privilege escalation
- Data exfiltration
- Tool abuse
- API abuse
- Credential theft
- Agent manipulation

Required controls:

- Prompt separation
- Instruction filtering
- Document isolation
- Tool authorization checks
- Structured audit logging
- Human approval for sensitive operations

