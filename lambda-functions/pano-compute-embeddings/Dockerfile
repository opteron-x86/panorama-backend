# lambda-functions/pano-generate-embeddings/Dockerfile
FROM public.ecr.aws/lambda/python:3.13

RUN pip install --no-cache-dir \
    onnxruntime \
    transformers \
    numpy \
    psycopg2-binary \
    sqlalchemy \
    pydantic \
    boto3

COPY lambda_function.py .
COPY panorama_datamodel/ ./panorama_datamodel/

CMD ["lambda_function.lambda_handler"]