# Linux Terminal Commander

Initial source snapshot of the Python MCP-based Ubuntu Commander 5.1 implementation.

**Status: development snapshot, not yet a portable installer or a security-audited release.**

This initial commit preserves the source and tests for later generalization. The code still contains example machine paths, project-specific behaviors and a service template requiring configuration. Do not use it as a ready-to-run remote terminal.

Configuration, live tunnel profiles, local runtime data, backups, machine-specific root enrollment and generated files are deliberately excluded. Each future installation will need its own tunnel and locally authorized settings.

**Security warning:** The optional host-shell mode grants remote commands the privileges of the Linux user running the server. Restrict remote access to trusted accounts and prefer isolated mode until reviewed.

See the official OpenAI tunnel-client project for its own license and setup instructions. No tunnel-client binary is distributed here.