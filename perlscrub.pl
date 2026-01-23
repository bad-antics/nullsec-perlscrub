#!/usr/bin/env perl
#
# NullSec PerlScrub - Log Sanitization and Analysis Engine
# Perl security tool demonstrating:
#   - Regular expressions (PCRE)
#   - Text processing
#   - Hash data structures
#   - File handling
#   - Pattern matching operators
#   - Object-oriented Perl (Moose-style)
#
# Author: bad-antics
# License: MIT

use strict;
use warnings;
use v5.20;
use feature qw(signatures);
no warnings qw(experimental::signatures);

our $VERSION = "1.0.0";

# ANSI Colors
my %COLORS = (
    red    => "\e[31m",
    green  => "\e[32m",
    yellow => "\e[33m",
    cyan   => "\e[36m",
    gray   => "\e[90m",
    reset  => "\e[0m",
);

sub colorize($color, $text) {
    return $COLORS{$color} . $text . $COLORS{reset};
}

# Risk levels
use constant {
    RISK_CRITICAL => 4,
    RISK_HIGH     => 3,
    RISK_MEDIUM   => 2,
    RISK_LOW      => 1,
    RISK_INFO     => 0,
};

# Sensitive patterns to detect and redact
my @SENSITIVE_PATTERNS = (
    {
        name    => "Credit Card",
        pattern => qr/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
        risk    => "critical",
        mitre   => "T1552",
        cwe     => "CWE-312",
    },
    {
        name    => "SSN",
        pattern => qr/\b\d{3}-\d{2}-\d{4}\b/,
        risk    => "critical",
        mitre   => "T1552",
        cwe     => "CWE-312",
    },
    {
        name    => "Email Address",
        pattern => qr/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        risk    => "medium",
        mitre   => "T1589",
        cwe     => "CWE-359",
    },
    {
        name    => "IPv4 Address",
        pattern => qr/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
        risk    => "low",
        mitre   => "T1590",
        cwe     => "CWE-359",
    },
    {
        name    => "AWS Access Key",
        pattern => qr/\bAKIA[0-9A-Z]{16}\b/,
        risk    => "critical",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "Private Key Header",
        pattern => qr/-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
        risk    => "critical",
        mitre   => "T1552",
        cwe     => "CWE-321",
    },
    {
        name    => "Password Field",
        pattern => qr/(?:password|passwd|pwd)\s*[=:]\s*["']?[^"'\s]{4,}["']?/i,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-312",
    },
    {
        name    => "API Key Pattern",
        pattern => qr/(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*["']?[a-zA-Z0-9]{16,}["']?/i,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "Bearer Token",
        pattern => qr/Bearer\s+[a-zA-Z0-9\-_.~+\/]+=*/,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "Basic Auth",
        pattern => qr/Basic\s+[A-Za-z0-9+\/]+=*/,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "JWT Token",
        pattern => qr/eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}/,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "Database URL",
        pattern => qr/(?:postgres|mysql|mongodb|redis):\/\/[^\s]+/i,
        risk    => "high",
        mitre   => "T1552",
        cwe     => "CWE-798",
    },
    {
        name    => "Phone Number",
        pattern => qr/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
        risk    => "medium",
        mitre   => "T1589",
        cwe     => "CWE-359",
    },
);

# Attack patterns to detect
my @ATTACK_PATTERNS = (
    {
        name    => "SQL Injection",
        pattern => qr/(?:union\s+select|'\s*or\s*'|drop\s+table|;\s*delete|;\s*update)/i,
        risk    => "critical",
        mitre   => "T1190",
        cwe     => "CWE-89",
    },
    {
        name    => "XSS Attempt",
        pattern => qr/<script[^>]*>|javascript:|on\w+\s*=/i,
        risk    => "high",
        mitre   => "T1189",
        cwe     => "CWE-79",
    },
    {
        name    => "Path Traversal",
        pattern => qr/\.\.\/|\.\.\\|%2e%2e%2f/i,
        risk    => "high",
        mitre   => "T1083",
        cwe     => "CWE-22",
    },
    {
        name    => "Command Injection",
        pattern => qr/;\s*(?:cat|ls|whoami|id|pwd|curl|wget|nc)\b|`[^`]+`|\$\([^)]+\)/,
        risk    => "critical",
        mitre   => "T1059",
        cwe     => "CWE-78",
    },
    {
        name    => "LDAP Injection",
        pattern => qr/[)(|*\\]\s*[)(|*\\]/,
        risk    => "high",
        mitre   => "T1190",
        cwe     => "CWE-90",
    },
    {
        name    => "Log Injection",
        pattern => qr/%0[aAdD]|\\r|\\n/,
        risk    => "medium",
        mitre   => "T1070",
        cwe     => "CWE-117",
    },
);

# Finding structure
package Finding {
    sub new($class, %args) {
        my $self = {
            line_number => $args{line_number},
            content     => $args{content},
            pattern     => $args{pattern},
            risk        => $args{risk},
            mitre       => $args{mitre},
            cwe         => $args{cwe},
            type        => $args{type},
        };
        return bless $self, $class;
    }
}

package main;

# Risk to color mapping
sub risk_color($risk) {
    my %mapping = (
        critical => 'red',
        high     => 'red',
        medium   => 'yellow',
        low      => 'cyan',
        info     => 'gray',
    );
    return $mapping{$risk} // 'gray';
}

# Risk score mapping
sub risk_score($risk) {
    my %mapping = (
        critical => RISK_CRITICAL,
        high     => RISK_HIGH,
        medium   => RISK_MEDIUM,
        low      => RISK_LOW,
        info     => RISK_INFO,
    );
    return $mapping{$risk} // RISK_INFO;
}

# Analyze line for sensitive data
sub analyze_line($line, $line_num) {
    my @findings;
    
    # Check sensitive patterns
    for my $pat (@SENSITIVE_PATTERNS) {
        if ($line =~ $pat->{pattern}) {
            push @findings, Finding->new(
                line_number => $line_num,
                content     => $line,
                pattern     => $pat->{name},
                risk        => $pat->{risk},
                mitre       => $pat->{mitre},
                cwe         => $pat->{cwe},
                type        => 'sensitive',
            );
        }
    }
    
    # Check attack patterns
    for my $pat (@ATTACK_PATTERNS) {
        if ($line =~ $pat->{pattern}) {
            push @findings, Finding->new(
                line_number => $line_num,
                content     => $line,
                pattern     => $pat->{name},
                risk        => $pat->{risk},
                mitre       => $pat->{mitre},
                cwe         => $pat->{cwe},
                type        => 'attack',
            );
        }
    }
    
    return @findings;
}

# Redact sensitive data from line
sub redact_line($line) {
    my $redacted = $line;
    
    for my $pat (@SENSITIVE_PATTERNS) {
        $redacted =~ s/$pat->{pattern}/[REDACTED:$pat->{name}]/g;
    }
    
    return $redacted;
}

# Demo log lines
my @DEMO_LOGS = (
    '2024-01-15 10:23:45 INFO User login: user@example.com from 192.168.1.100',
    '2024-01-15 10:24:12 DEBUG Payment processed: CC 4111111111111111 exp 12/25',
    '2024-01-15 10:24:30 ERROR Failed auth for SSN 123-45-6789',
    '2024-01-15 10:25:00 WARN API call with key: api_key=sk_live_abcdef1234567890',
    '2024-01-15 10:25:15 INFO Request: GET /search?q=\' UNION SELECT * FROM users--',
    '2024-01-15 10:25:30 DEBUG Auth header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abcd',
    '2024-01-15 10:26:00 ERROR <script>alert(\'XSS\')</script> in comment field',
    '2024-01-15 10:26:15 INFO Database: postgres://user:secretpass@db.example.com:5432/app',
    '2024-01-15 10:26:30 WARN Path traversal attempt: ../../etc/passwd',
    '2024-01-15 10:27:00 DEBUG password=SuperSecret123! in config',
    '2024-01-15 10:27:15 INFO Contact phone: (555) 123-4567',
    '2024-01-15 10:27:30 ERROR Command injection: ; cat /etc/shadow',
    '2024-01-15 10:28:00 INFO Normal log entry with no sensitive data',
);

# Print banner
sub print_banner() {
    print "\n";
    print "╔══════════════════════════════════════════════════════════════════╗\n";
    print "║          NullSec PerlScrub - Log Sanitization Engine             ║\n";
    print "╚══════════════════════════════════════════════════════════════════╝\n";
    print "\n";
}

# Print usage
sub print_usage() {
    print "USAGE:\n";
    print "    perlscrub [OPTIONS] <LOGFILE>\n";
    print "\n";
    print "OPTIONS:\n";
    print "    -h, --help       Show this help\n";
    print "    -r, --redact     Redact sensitive data\n";
    print "    -a, --attacks    Detect attack patterns\n";
    print "    -o, --output     Output file\n";
    print "\n";
    print "FEATURES:\n";
    print "    • Sensitive data detection\n";
    print "    • Attack pattern recognition\n";
    print "    • Automatic redaction\n";
    print "    • PCRE regex matching\n";
}

# Print finding
sub print_finding($finding) {
    my $color = risk_color($finding->{risk});
    my $risk_str = uc($finding->{risk});
    my $type_str = $finding->{type} eq 'attack' ? 'ATTACK' : 'SENSITIVE';
    
    print "\n";
    print "  " . colorize($color, "[$risk_str]") . " $finding->{pattern} ($type_str)\n";
    print "    Line:    $finding->{line_number}\n";
    print "    Content: " . substr($finding->{content}, 0, 60) . "...\n" if length($finding->{content}) > 60;
    print "    Content: $finding->{content}\n" if length($finding->{content}) <= 60;
    print "    MITRE:   $finding->{mitre}\n";
    print "    CWE:     $finding->{cwe}\n";
}

# Print summary
sub print_summary($findings, $total_lines) {
    my $critical = scalar grep { $_->{risk} eq 'critical' } @$findings;
    my $high = scalar grep { $_->{risk} eq 'high' } @$findings;
    my $medium = scalar grep { $_->{risk} eq 'medium' } @$findings;
    my $sensitive = scalar grep { $_->{type} eq 'sensitive' } @$findings;
    my $attacks = scalar grep { $_->{type} eq 'attack' } @$findings;
    
    print "\n";
    print colorize('gray', "═══════════════════════════════════════════") . "\n";
    print "\n";
    print "  Summary:\n";
    print "    Lines Analyzed:  $total_lines\n";
    print "    Findings:        " . scalar(@$findings) . "\n";
    print "    Sensitive Data:  $sensitive\n";
    print "    Attack Patterns: $attacks\n";
    print "    Critical:        " . colorize('red', $critical) . "\n";
    print "    High:            " . colorize('red', $high) . "\n";
    print "    Medium:          " . colorize('yellow', $medium) . "\n";
}

# Demo mode
sub demo() {
    print colorize('yellow', "[Demo Mode]") . "\n";
    print "\n";
    print colorize('cyan', "Analyzing log entries for sensitive data and attacks...") . "\n";
    
    my @all_findings;
    my $line_num = 0;
    
    for my $line (@DEMO_LOGS) {
        $line_num++;
        my @findings = analyze_line($line, $line_num);
        push @all_findings, @findings;
    }
    
    # Sort by risk
    @all_findings = sort { risk_score($b->{risk}) <=> risk_score($a->{risk}) } @all_findings;
    
    for my $f (@all_findings) {
        print_finding($f);
    }
    
    print_summary(\@all_findings, scalar @DEMO_LOGS);
    
    # Show redaction example
    print "\n";
    print colorize('cyan', "Sample Redacted Output:") . "\n";
    print "\n";
    for my $line (@DEMO_LOGS[0..4]) {
        print "  " . redact_line($line) . "\n";
    }
}

# Main entry point
sub main(@args) {
    print_banner();
    
    if (!@args || grep { $_ eq '-h' || $_ eq '--help' } @args) {
        print_usage();
        print "\n";
        demo();
    } elsif (grep { $_ eq '--demo' } @args) {
        demo();
    } else {
        print_usage();
    }
}

main(@ARGV);
