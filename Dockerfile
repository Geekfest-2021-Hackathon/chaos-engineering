FROM python:3.9

COPY . /app

RUN cd app

RUN pip install -r requirements.txt

CMD ["/bin/sh"]
