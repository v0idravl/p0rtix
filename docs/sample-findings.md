# Sample p0rtix findings output (sanitized)

This abbreviated example uses documentation-only targets and placeholder names. It is not output from a real assessment.

```text
Target: 192.0.2.10
Domain: example.internal
Mode: authorized internal assessment
```

## Port Discovery

- TCP open: 80, 445
- UDP open: none confirmed

## Service Findings

### TCP 80 — HTTP

> `curl -i http://192.0.2.10/`

- Server header: ExampleServer/1.0
- Redirect target: `http://portal.example.internal/`

### TCP 445 — SMB

> `nmap --script smb-os-discovery,smb-enum-shares -p 445 192.0.2.10`

- Hostname: FILE01
- Shares: IPC$ (NO ACCESS), Public (READ)

## External Links

- `https://example.com/vendor-docs` — recorded as external evidence only; not crawled or scanned.

## Key Findings

- Internal portal vhost discovered: `portal.example.internal`
- Readable SMB share identified: `Public`

## Notices

- Out-of-scope links were preserved in findings but not followed by enumeration tools.
