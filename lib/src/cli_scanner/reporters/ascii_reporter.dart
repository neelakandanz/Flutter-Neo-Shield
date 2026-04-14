import '../finding.dart';
import '../scan_result.dart';
import 'reporter.dart';

const _reset = '\x1B[0m';
const _bold = '\x1B[1m';
const _dim = '\x1B[2m';
const _green = '\x1B[32m';
const _red = '\x1B[31m';
const _yellow = '\x1B[33m';
const _cyan = '\x1B[36m';
const _white = '\x1B[37m';
const _brightRed = '\x1B[91m';
const _bgRed = '\x1B[41m';
const _bgGreen = '\x1B[42m';

/// Color-coded ASCII terminal reporter with severity bars and score card.
class AsciiReporter extends Reporter {
  @override
  String format(ScanResult result) {
    final buf = StringBuffer();

    _writeBanner(buf);
    _writeSummaryBox(buf, result);
    _writeSeverityBar(buf, result);

    if (result.findings.isNotEmpty) {
      _writeFindingsByCategory(buf, result);
    }

    _writeScoreCard(buf, result);
    _writeFooter(buf, result);

    return buf.toString();
  }

  void _writeBanner(StringBuffer buf) {
    buf.writeln();
    buf.writeln('$_bold$_cyan╔══════════════════════════════════════════════════════════════╗$_reset');
    buf.writeln('$_bold$_cyan║          flutter_neo_shield — Security Scanner              ║$_reset');
    buf.writeln('$_bold$_cyan║                   Advanced Deep Analysis                    ║$_reset');
    buf.writeln('$_bold$_cyan╚══════════════════════════════════════════════════════════════╝$_reset');
    buf.writeln();
  }

  void _writeSummaryBox(StringBuffer buf, ScanResult result) {
    buf.writeln('$_bold  SCAN SUMMARY$_reset');
    buf.writeln('$_dim  ─────────────────────────────────────────$_reset');
    buf.writeln('  Project:  ${result.projectPath}');
    buf.writeln('  Mode:     ${result.scanMode}');
    buf.writeln('  Files:    ${result.filesScanned} scanned');
    buf.writeln('  Duration: ${result.duration.inMilliseconds}ms');
    buf.writeln('  Findings: ${result.totalFindings}');
    buf.writeln();
  }

  void _writeSeverityBar(StringBuffer buf, ScanResult result) {
    final c = result.criticalCount;
    final h = result.highCount;
    final m = result.mediumCount;
    final l = result.lowCount;
    final i = result.infoCount;

    buf.writeln('$_bold  SEVERITY BREAKDOWN$_reset');
    buf.writeln('$_dim  ─────────────────────────────────────────$_reset');
    buf.writeln('  ${_brightRed}CRITICAL$_reset  $c ${_makeBar(c, result.totalFindings, _brightRed)}');
    buf.writeln('  ${_red}HIGH$_reset      $h ${_makeBar(h, result.totalFindings, _red)}');
    buf.writeln('  ${_yellow}MEDIUM$_reset    $m ${_makeBar(m, result.totalFindings, _yellow)}');
    buf.writeln('  ${_cyan}LOW$_reset       $l ${_makeBar(l, result.totalFindings, _cyan)}');
    buf.writeln('  ${_white}INFO$_reset      $i ${_makeBar(i, result.totalFindings, _white)}');
    buf.writeln();
  }

  String _makeBar(int count, int total, String color) {
    if (total == 0) return '';
    const width = 30;
    final filled = total > 0 ? (count * width / total).round() : 0;
    return '$color${'█' * filled}${'░' * (width - filled)}$_reset';
  }

  void _writeFindingsByCategory(StringBuffer buf, ScanResult result) {
    buf.writeln('$_bold  FINDINGS BY CATEGORY$_reset');
    buf.writeln('$_dim  ═════════════════════════════════════════$_reset');

    final byCategory = result.findingsByCategory;
    final sortedCategories = byCategory.keys.toList()
      ..sort((a, b) {
        final aMax = byCategory[a]!
            .map((f) => f.severity.weight)
            .reduce((a, b) => a > b ? a : b);
        final bMax = byCategory[b]!
            .map((f) => f.severity.weight)
            .reduce((a, b) => a > b ? a : b);
        return bMax.compareTo(aMax);
      });

    for (final category in sortedCategories) {
      final findings = byCategory[category]!;
      buf.writeln();
      buf.writeln('  $_bold$category$_reset (${findings.length} findings)');
      buf.writeln('  $_dim${'─' * 50}$_reset');

      for (final f in findings) {
        _writeFinding(buf, f);
      }
    }
    buf.writeln();
  }

  void _writeFinding(StringBuffer buf, Finding f) {
    final color = f.severity.ansiColor;
    final icon = f.severity.icon;
    buf.writeln('  $color$icon $_bold${f.title}$_reset');
    buf.writeln('      $_dim${f.filePath}:${f.lineNumber}$_reset');
    if (f.matchedText.length <= 120) {
      buf.writeln('      Match: ${f.matchedText}');
    } else {
      buf.writeln('      Match: ${f.matchedText.substring(0, 117)}...');
    }
    buf.writeln('      Fix: ${f.rule.recommendation}');
    buf.writeln();
  }

  void _writeScoreCard(StringBuffer buf, ScanResult result) {
    buf.writeln('$_dim  ═════════════════════════════════════════$_reset');
    buf.writeln();

    final gradeColor = switch (result.grade) {
      'A' => _green,
      'B' => _cyan,
      'C' => _yellow,
      'D' => _red,
      _ => _brightRed,
    };

    buf.writeln('  $_bold SECURITY SCORE$_reset');
    buf.writeln();
    buf.writeln('       $gradeColor$_bold ┌─────────┐$_reset');
    buf.writeln('       $gradeColor$_bold │  ${result.score.toString().padLeft(3)}    │$_reset');
    buf.writeln('       $gradeColor$_bold │  /100   │$_reset');
    buf.writeln('       $gradeColor$_bold │ Grade ${result.grade} │$_reset');
    buf.writeln('       $gradeColor$_bold └─────────┘$_reset');
    buf.writeln();
  }

  void _writeFooter(StringBuffer buf, ScanResult result) {
    if (result.passed) {
      buf.writeln('  $_bgGreen$_bold PASS $_reset No critical or high severity issues found.');
    } else {
      buf.writeln('  $_bgRed$_bold FAIL $_reset ${result.criticalCount} critical, ${result.highCount} high severity issues require attention.');
    }
    buf.writeln();
    buf.writeln('  $_dim Powered by flutter_neo_shield v2.1.1$_reset');
    buf.writeln('  $_dim Run with --format json for CI/CD integration$_reset');
    buf.writeln();
  }
}
