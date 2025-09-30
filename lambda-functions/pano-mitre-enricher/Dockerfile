# lambda-functions/pano-mitre-enricher/Dockerfile
FROM public.ecr.aws/lambda/python:3.13

RUN pip install --no-cache-dir \
    onnxruntime \
    transformers \
    numpy \
    psycopg2-binary \
    sqlalchemy \
    pydantic \
    boto3

COPY *.py ${LAMBDA_TASK_ROOT}/
COPY panorama_datamodel/ ${LAMBDA_TASK_ROOT}/panorama_datamodel/

CMD ["lambda_function.lambda_handler"]