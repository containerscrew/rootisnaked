global:
  resolve_timeout: 5m

# basic_auth:
#   username: elliot
#   password: adminadmin@
#   #  password_file: <string>

route:
  group_wait: 5s
  receiver: noop
  routes:
    - receiver: telegram_receiver
      matchers:
        - severity =~ "critical"
    - receiver: noop
      matchers:
        - severity =~ "warning|info"

receivers:
  - name: noop
  - name: telegram_receiver
    telegram_configs:
      - bot_token: ${TELEGRAM_BOT_TOKEN}
        chat_id: ${TELEGRAM_CHAT_ID}
        send_resolved: false
        parse_mode: "MarkdownV2"
        message: |
          {{ range .Alerts -}}
          *{{ .Status | toUpper }}* – {{ .Labels.alertname }}
          {{ if .Labels.severity }}*Severity:* `{{ .Labels.severity }}`{{ end }}
          {{ if .Annotations.title }}*Title:* {{ .Annotations.title }}{{ end }}
          {{ if .Annotations.description }}*Description:* {{ .Annotations.description }}{{ end }}

          *Details:*
          {{ range .Labels.SortedPairs }} • *{{ .Name }}*: `{{ .Value }}`
          {{ end }}

          {{ if .Annotations.runbook_url }}*Runbook:* {{ .Annotations.runbook_url }}{{ end }}
          {{ end }}
