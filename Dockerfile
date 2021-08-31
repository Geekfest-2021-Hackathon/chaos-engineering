FROM python:3.9

COPY requirements.txt /app/requirements.txt

RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY . /app

WORKDIR /app

EXPOSE 9060

RUN apt-get update && apt-get install -y vim bsdmainutils

RUN echo 'export PS1="chaos> "' >> /root/.bashrc

CMD ["uvicorn", "samples.apifuzzer.main:app", "--host", "0.0.0.0", "--port", "9060"]
