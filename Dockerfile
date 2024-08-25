# hadolint global ignore=DL3008
FROM python:3-bookworm

WORKDIR /app

RUN apt-get update &&                                           \
    apt-get install -y openjdk-17-jre-headless &&               \
    apt-get clean &&                                            \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN wget -q https://mark0.net/download/trid_linux_64.zip &&                                                     \
    wget -q https://mark0.net/download/triddefs.zip &&                                                          \
    wget -q https://gitlab.freedesktop.org/xdg/shared-mime-info/-/raw/master/data/freedesktop.org.xml.in &&     \
    python3 -m zipfile -e trid_linux_64.zip /usr/bin &&                                                         \
    rm trid_linux_64.zip &&                                                                                     \
    python3 -m zipfile -e triddefs.zip /usr/bin &&                                                              \
    rm triddefs.zip &&                                                                                          \
    chmod +x /usr/bin/trid

COPY filetype.py .
CMD ["python3", "filetype.py"]
