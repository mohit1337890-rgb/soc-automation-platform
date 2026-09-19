FROM python:3.11-slim

WORKDIR /app

# System deps kept minimal on purpose - this image only needs to run pure
# Python (no compiled GeoIP/EVTX libs are required by the current detectors).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data/, sample_data/ and reports/ are meant to be mounted as volumes
# (see docker-compose.yml) so a container restart never loses a client's
# alert history.
RUN mkdir -p data sample_data reports

EXPOSE 8501

# Default command runs the web dashboard - `docker compose up` alone should
# give a client a working product with zero extra steps.
CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
