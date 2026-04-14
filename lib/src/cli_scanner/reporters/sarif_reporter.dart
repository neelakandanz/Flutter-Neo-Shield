import 'dart:convert';

import '../finding.dart';
import '../scan_result.dart';
import '../severity.dart';
import 'reporter.dart';

/// SARIF 2.1.0 format reporter for GitHub Advanced Security integration.
class SarifReporter extends Reporter {
  @override
  String format(ScanResult result) {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(_buildSarif(result));
  }

  Map<String, dynamic> _buildSarif(ScanResult result) {
    final uniqueRules = <String, Map<String, dynamic>>{};
    for (final f in result.findings) {
      uniqueRules.putIfAbsent(f.ruleId, () => _buildRule(f));
    }

    // Build ruleId -> index map for ruleIndex references
    final ruleIds = uniqueRules.keys.toList();

    return {
      '\$schema':
          'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      'version': '2.1.0',
      'runs': [
        {
          'tool': {
            'driver': {
              'name': 'flutter_neo_shield',
              'version': '2.1.1',
              'informationUri':
                  'https://github.com/neelakandanz/flutter-neo-shield',
              'rules': uniqueRules.values.toList(),
            },
          },
          'results':
              result.findings.map((f) => _buildResult(f, ruleIds)).toList(),
        },
      ],
    };
  }

  Map<String, dynamic> _buildRule(Finding f) => {
        'id': f.ruleId,
        'name': f.title,
        'shortDescription': {'text': f.title},
        'fullDescription': {'text': f.rule.description},
        'helpUri':
            'https://github.com/neelakandanz/flutter-neo-shield#security-scanner',
        'defaultConfiguration': {
          'level': _sarifLevel(f.severity),
        },
        'properties': {
          'tags': ['security', f.category],
        },
      };

  Map<String, dynamic> _buildResult(Finding f, List<String> ruleIds) => {
        'ruleId': f.ruleId,
        'ruleIndex': ruleIds.indexOf(f.ruleId),
        'level': _sarifLevel(f.severity),
        'message': {
          'text':
              '${f.rule.description}\n\nRecommendation: ${f.rule.recommendation}',
        },
        'locations': [
          {
            'physicalLocation': {
              'artifactLocation': {
                'uri': _toUri(f.filePath),
                'uriBaseId': '%SRCROOT%',
              },
              'region': {
                'startLine': f.lineNumber,
              },
            },
          },
        ],
      };

  String _toUri(String path) {
    // Normalize separators and percent-encode special characters
    final normalized = path.replaceAll('\\', '/');
    return Uri.encodeFull(normalized);
  }

  String _sarifLevel(Severity s) => switch (s) {
        Severity.critical || Severity.high => 'error',
        Severity.medium => 'warning',
        Severity.low || Severity.info => 'note',
      };
}
