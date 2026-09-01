Size 1200x800
Theme Dark
Shell bash
FontSize 16
Margin 40
Padding 20

# Title screen
type "🛡️  Sentinel — Code review that proves it's right"
enter
sleep 1.5s

# Scan
type ""
type "sentinel scan demo-project/"
enter
sleep 3s

# Show verify
type ""
type "sentinel scan demo-project/ --verify"
enter
sleep 3s

# Show rules
type ""
type "sentinel rules 2>&1 | head -20"
enter
sleep 2s

# Show JSON output
type ""
type "sentinel scan demo-project/ --format json 2>&1 | python3 -c \"import sys,json; d=json.load(sys.stdin); print(json.dumps(d['summary'], indent=2))\""
enter
sleep 2s
