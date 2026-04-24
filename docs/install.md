# Installation

Pick the path that fits how you work.

## Docker (recommended)

```bash
docker run -d -p 8501:8501 --name netwatchai udayak/netwatchai:latest
```

Open http://localhost:8501. The first-run password is printed in the container logs:

```bash
docker logs netwatchai | grep "Generated password"
```

!!! tip "Persistent data"
    Mount a volume so alerts, config, and the allowlist survive container rebuilds:

    ```bash
    docker run -d -p 8501:8501 -v netwatchai-data:/app/data udayak/netwatchai:latest
    ```

## pip

```bash
pip install netwatchai
netwatchai-train
netwatchai-dashboard
```

## From source

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python train.py
streamlit run dashboard.py
```

## Raspberry Pi / Apple Silicon

The Docker image ships for both `linux/amd64` and `linux/arm64`. The same `docker run`
command works on a Raspberry Pi 4, an M-series Mac, and an x86 server.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `NETWATCHAI_PASSWORD` | Override the generated admin password | Random on first boot |
| `PORT` | Port for the Streamlit dashboard | `8501` |
