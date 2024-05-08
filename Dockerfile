FROM python:3.12.3-slim-bookworm

WORKDIR /app
COPY poetry.lock pyproject.toml /app/

RUN pip install poetry


RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi

COPY . /app



CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]