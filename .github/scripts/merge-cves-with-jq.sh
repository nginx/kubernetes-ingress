#!/bin/sh

jq -n '
  def basename: sub("^.*/";"");
  def sev_rank($s): ({"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"UNKNOWN":0}[$s] // 0);

  [ inputs
    | (input_filename | basename) as $src
    | .runs[]?.tool.driver.rules[]?
    | select(.id? and (.id|test("^CVE-")))
    | {
        cve: .id,
        source: $src,

        severity: (.properties.cvssV3_severity // null),
        cvss: (.properties.cvssV3 // empty),
        description: (.help.text // .shortDescription.text // ""),
        fixed_version: (.properties.fixed_version // null),
        purls: (.properties.purls // [])
      }
  ]
  | group_by(.cve)
  | map(. as $g | {
      cve: $g[0].cve,
      sources: ($g | map(.source) | unique | sort),

      severity: (
        ($g | map(.severity) | map(select(.!=null)) | unique)
        | sort_by(sev_rank(.)) | last // null
      ),

      cvss: ($g | map(.cvss) | unique | sort),
      purls: ($g | map(.purls) | add | unique | sort),
      description: ($g | map(.description) | map(select(. != "")) | .[0] // ""),
      fixed_version: ($g | map(.fixed_version) | map(select(.!=null)) | unique | sort),
      fixable: ($g | any((.fixed_version // "") | (. != "" and . != "not fixed")))
    })
  | sort_by(.cve)
' ./../../reports/*.sarif.json > ./../../reports/merged-cves.json
