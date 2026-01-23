# NullSec PerlScrub

**Log Sanitization and Analysis Engine** written in Perl

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-perlscrub/releases)
[![Language](https://img.shields.io/badge/language-Perl-39457E.svg)](https://www.perl.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Discord: [discord.gg/killers](https://discord.gg/killers)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

PerlScrub is a powerful log analysis and sanitization tool that detects sensitive data exposure and attack patterns in log files. Built with Perl's legendary regex capabilities (PCRE), it excels at text processing, pattern matching, and automatic data redaction.

## Perl Features Showcased

- **PCRE Regex**: Advanced pattern matching
- **Hash Structures**: Flexible data organization
- **Subroutine Signatures**: Modern Perl syntax
- **Package System**: OOP-style classes
- **File Handling**: Efficient I/O
- **Array/Hash Manipulation**: Text processing power
- **Regex Operators**: `=~`, `s///`, `qr//`

## Detected Patterns

### Sensitive Data

| Pattern | Risk | CWE | Description |
|---------|------|-----|-------------|
| Credit Card | CRITICAL | CWE-312 | Card numbers (Visa/MC/Amex) |
| SSN | CRITICAL | CWE-312 | Social Security Numbers |
| AWS Keys | CRITICAL | CWE-798 | AWS Access Key IDs |
| Private Keys | CRITICAL | CWE-321 | RSA/EC private key headers |
| Passwords | HIGH | CWE-312 | Password assignments |
| API Keys | HIGH | CWE-798 | Generic API key patterns |
| JWT Tokens | HIGH | CWE-798 | JSON Web Tokens |
| Bearer Tokens | HIGH | CWE-798 | OAuth bearer tokens |
| Database URLs | HIGH | CWE-798 | Connection strings |
| Email Addresses | MEDIUM | CWE-359 | PII exposure |
| Phone Numbers | MEDIUM | CWE-359 | Contact information |
| IP Addresses | LOW | CWE-359 | Network identifiers |

### Attack Patterns

| Pattern | Risk | MITRE | Description |
|---------|------|-------|-------------|
| SQL Injection | CRITICAL | T1190 | UNION/OR attacks |
| Command Injection | CRITICAL | T1059 | Shell commands |
| XSS | HIGH | T1189 | Script injection |
| Path Traversal | HIGH | T1083 | Directory escape |
| LDAP Injection | HIGH | T1190 | LDAP filter manipulation |
| Log Injection | MEDIUM | T1070 | CRLF injection |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-perlscrub.git
cd nullsec-perlscrub

# Run (requires Perl 5.20+)
perl perlscrub.pl <logfile>
```

## Usage

```bash
# Analyze a log file
perl perlscrub.pl /var/log/app.log

# Run demo mode
perl perlscrub.pl --demo

# Redact sensitive data
perl perlscrub.pl -r input.log > sanitized.log

# Detect attacks only
perl perlscrub.pl -a /var/log/apache/access.log
```

### Options

```
USAGE:
    perlscrub [OPTIONS] <LOGFILE>

OPTIONS:
    -h, --help       Show help
    -r, --redact     Redact sensitive data
    -a, --attacks    Detect attack patterns
    -o, --output     Output file
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║          NullSec PerlScrub - Log Sanitization Engine             ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing log entries for sensitive data and attacks...

  [CRITICAL] Credit Card (SENSITIVE)
    Line:    2
    Content: 2024-01-15 10:24:12 DEBUG Payment processed: CC 4111111...
    MITRE:   T1552
    CWE:     CWE-312

  [CRITICAL] SQL Injection (ATTACK)
    Line:    5
    Content: 2024-01-15 10:25:15 INFO Request: GET /search?q=' UNION...
    MITRE:   T1190
    CWE:     CWE-89

  [HIGH] Password Field (SENSITIVE)
    Line:    10
    Content: 2024-01-15 10:27:00 DEBUG password=SuperSecret123! in config
    MITRE:   T1552
    CWE:     CWE-312

═══════════════════════════════════════════

  Summary:
    Lines Analyzed:  13
    Findings:        15
    Sensitive Data:  10
    Attack Patterns: 5
    Critical:        4
    High:            7
    Medium:          4

Sample Redacted Output:

  2024-01-15 10:23:45 INFO User login: [REDACTED:Email Address] from [REDACTED:IPv4 Address]
  2024-01-15 10:24:12 DEBUG Payment processed: CC [REDACTED:Credit Card] exp 12/25
```

## Code Highlights

### PCRE Pattern Definitions
```perl
my @SENSITIVE_PATTERNS = (
    {
        name    => "Credit Card",
        pattern => qr/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/,
        risk    => "critical",
        cwe     => "CWE-312",
    },
    {
        name    => "SQL Injection",
        pattern => qr/(?:union\s+select|'\s*or\s*'|drop\s+table)/i,
        risk    => "critical",
        cwe     => "CWE-89",
    },
);
```

### Line Analysis with Regex
```perl
sub analyze_line($line, $line_num) {
    my @findings;
    
    for my $pat (@SENSITIVE_PATTERNS) {
        if ($line =~ $pat->{pattern}) {
            push @findings, Finding->new(
                line_number => $line_num,
                content     => $line,
                pattern     => $pat->{name},
                risk        => $pat->{risk},
            );
        }
    }
    
    return @findings;
}
```

### Automatic Redaction
```perl
sub redact_line($line) {
    my $redacted = $line;
    
    for my $pat (@SENSITIVE_PATTERNS) {
        $redacted =~ s/$pat->{pattern}/[REDACTED:$pat->{name}]/g;
    }
    
    return $redacted;
}
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   PerlScrub Architecture                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │  Log File   │───▶│   Parser    │───▶│  Line by    │      │
│    │  Input      │    │             │    │  Line       │      │
│    └─────────────┘    └─────────────┘    └──────┬──────┘      │
│                                                  │             │
│         ┌────────────────┬───────────────────────┘             │
│         ▼                ▼                                     │
│    ┌──────────┐    ┌──────────┐                               │
│    │ Sensitive│    │  Attack  │                               │
│    │ Patterns │    │ Patterns │                               │
│    └────┬─────┘    └────┬─────┘                               │
│         │               │                                      │
│         └───────┬───────┘                                      │
│                 ▼                                              │
│    ┌──────────────────────┐    ┌──────────────────┐           │
│    │      Findings        │───▶│  Redact / Report │           │
│    │     Collection       │    │                  │           │
│    └──────────────────────┘    └──────────────────┘           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why Perl?

| Requirement | Perl Advantage |
|-------------|----------------|
| Text Processing | Native strength |
| Regex Power | PCRE built-in |
| Log Analysis | Designed for it |
| String Manipulation | Unmatched |
| Quick Scripts | Rapid development |
| Unix Integration | Perfect fit |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-reporaider](https://github.com/bad-antics/nullsec-reporaider) - Secret scanner (Clojure)
- [nullsec-shelltrace](https://github.com/bad-antics/nullsec-shelltrace) - Shell auditor (Tcl)
- [nullsec-luashield](https://github.com/bad-antics/nullsec-luashield) - WAF engine (Lua)
