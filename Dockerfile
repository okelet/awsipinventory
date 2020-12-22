FROM python:3.8

RUN useradd -ms /bin/bash user
USER user
ENV PATH=$PATH:/home/user/.local/bin
WORKDIR /home/user

COPY --chown=user:user . /app
RUN pip3 install --user /app

ENTRYPOINT ["/home/user/.local/bin/awsipinventory"]
