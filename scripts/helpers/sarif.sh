#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch SARIF formatter ─────────────────────────────────────────────
# Converts ClawPinch findings JSON to SARIF v2.1.0 format for GitHub Code
# Scanning and other static analysis platforms.

# Ensure common helpers are available
if [[ -z "${_CLAWPINCH_HAS_COLOR:-}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=scripts/helpers/common.sh
  source "$SCRIPT_DIR/common.sh"
fi

# ─── SARIF converter ──────────────────────────────────────────────────────
# Usage: convert_to_sarif <findings_json>
#   findings_json: JSON array of ClawPinch findings
#
# Outputs: Valid SARIF v2.1.0 JSON to stdout

convert_to_sarif() {
  local findings_json="${1:-[]}"

  # Require jq for SARIF generation
  if ! require_cmd jq; then
    log_error "jq is required for SARIF output"
    return 1
  fi

  # Get tool version from package.json (fallback to 1.2.1)
  local tool_version="1.2.1"
  local package_json
  package_json="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/package.json"
  if [[ -f "$package_json" ]]; then
    tool_version="$(jq -r '.version // "1.2.1"' "$package_json" 2>/dev/null || echo "1.2.1")"
  fi

  # SARIF schema URL
  local sarif_schema="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

  # Tool information URI
  local tool_uri="https://github.com/MikeeBuilds/clawpinch"

  # Build SARIF document using jq
  echo "$findings_json" | jq -c \
    --arg schema "$sarif_schema" \
    --arg version "2.1.0" \
    --arg tool_name "clawpinch" \
    --arg tool_version "$tool_version" \
    --arg tool_uri "$tool_uri" \
    '{
      "$schema": $schema,
      "version": $version,
      "runs": [
        {
          "tool": {
            "driver": {
              "name": $tool_name,
              "version": $tool_version,
              "informationUri": $tool_uri,
              "rules": (
                . | [.[] | select(.severity != "ok")] | map({
                  id: .id,
                  name: .title,
                  shortDescription: {
                    text: .title
                  },
                  fullDescription: {
                    text: .description
                  },
                  helpUri: ($tool_uri + "/blob/main/references/check-catalog.md"),
                  defaultConfiguration: {
                    level: (
                      if .severity == "critical" then "error"
                      elif .severity == "warn" then "warning"
                      elif .severity == "info" then "note"
                      else "note"
                      end
                    )
                  },
                  properties: {
                    category: (
                      if .id | startswith("CHK-CFG-") then "configuration"
                      elif .id | startswith("CHK-SEC-") then "secrets"
                      elif .id | startswith("CHK-NET-") then "network"
                      elif .id | startswith("CHK-SKL-") then "skills"
                      elif .id | startswith("CHK-PRM-") then "permissions"
                      elif .id | startswith("CHK-CRN-") then "cron"
                      elif .id | startswith("CHK-CVE-") then "cve"
                      elif .id | startswith("CHK-SUP-") then "supply-chain"
                      else "general"
                      end
                    )
                  }
                })
                | unique_by(.id)
              )
            }
          },
          "results": (
            . | [.[] | select(.severity != "ok")] | map({
              "ruleId": .id,
              "level": (
                if .severity == "critical" then "error"
                elif .severity == "warn" then "warning"
                elif .severity == "info" then "note"
                else "note"
                end
              ),
              "message": {
                "text": .title,
                "markdown": (
                  if .remediation != "" then
                    (.description + "\n\n**Remediation:** " + .remediation)
                  else
                    .description
                  end
                )
              },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "."
                    }
                  }
                }
              ],
              "properties": {
                "evidence": .evidence,
                "auto_fix": .auto_fix
              }
            })
          )
        }
      ]
    }'
}

# ─── Main ──────────────────────────────────────────────────────────────────
# If this script is executed directly (not sourced), convert stdin to SARIF

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  findings="$(cat)"
  convert_to_sarif "$findings"
fi
