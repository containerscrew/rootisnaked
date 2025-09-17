global:
  resolve_timeout: 5m

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
        send_resolved: true
        parse_mode: "MarkdownV2"
        message: |
          {{ range .Alerts -}}
          *{{ .Status | toUpper }}* – {{ .Labels.alertname }}
          {{ if .Labels.severity }}*Severidad:* `{{ .Labels.severity }}`{{ end }}
          {{ if .Annotations.title }}*Título:* {{ .Annotations.title }}{{ end }}
          {{ if .Annotations.description }}*Descripción:* {{ .Annotations.description }}{{ end }}

          *Detalles:*
          {{ range .Labels.SortedPairs }} • *{{ .Name }}*: `{{ .Value }}`
          {{ end }}

          {{ if .Annotations.runbook_url }}*Runbook:* {{ .Annotations.runbook_url }}{{ end }}
          {{ end }}
