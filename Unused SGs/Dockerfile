FROM alpine:3.17.3

RUN apk add --update --no-cache py3-pip python3 && adduser -D task

USER task

WORKDIR /home/task

RUN pip3 install --upgrade boto3

COPY --chown=task:task unused_sgs.py /home/task/

CMD ["python3", "unused_sgs.py"]
