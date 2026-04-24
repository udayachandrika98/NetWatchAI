# NetWatchAI

**Network intrusion detection for people who don't have $30k/year to spend on Darktrace.**

NetWatchAI captures live traffic, detects anomalies with a lightweight ML model, and pings
you on Discord / Slack / email when something looks off. Runs in Docker. Takes 10 seconds
to start. Zero dollars.

---

## Why NetWatchAI

- **Free and open-source** — MIT licensed. Self-host it anywhere.
- **Real-time detection** — sub-5ms inference per packet on commodity hardware.
- **Free alert channels** — Discord, Slack, and SMTP email, all built in.
- **Low noise** — deduplication, allowlists, and a false-positive feedback button so it stops crying wolf.
- **Pretty** — a modern, opinionated dashboard that doesn't look like a 2005 enterprise product.

---

## 30-second demo

```bash
docker run -d -p 8501:8501 --name netwatchai udayak/netwatchai:latest
docker logs netwatchai | grep "Generated password"
open http://localhost:8501
```

## Next steps

- [Installation options](install.md) — pip, Docker, source, dev container.
- [Configure alerts](alerts.md) — Discord, Slack, email.
- [Architecture](architecture.md) — how the pipeline works.
