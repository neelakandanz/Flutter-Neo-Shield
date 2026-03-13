Pod::Spec.new do |s|
  s.name             = 'flutter_neo_shield'
  s.version          = '0.9.0'
  s.summary          = 'Client-side PII protection toolkit for Flutter.'
  s.description      = <<-DESC
  Client-side PII protection toolkit for Flutter — auto-scrubs sensitive data
  from logs, secures clipboard with timed auto-clear, and protects sensitive
  strings in memory.
                       DESC
  s.homepage         = 'https://github.com/neelakandanz/flutter-neo-shield'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Neelakandan' => 'dev@neelakandan.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '12.0'
  s.swift_version = '5.0'
end
