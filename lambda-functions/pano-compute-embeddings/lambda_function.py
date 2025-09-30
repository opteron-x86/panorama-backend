# lambda-functions/pano-generate-embeddings/lambda_function.py
import json
import boto3
import numpy as np
from panorama_datamodel import db_session
from panorama_datamodel.models import MitreTechnique

s3 = boto3.client('s3')
model_loaded = False
session = None
tokenizer = None

def load_model():
    global session, tokenizer, model_loaded
    if model_loaded:
        return
    
    # Upload model to S3 first, then download at runtime
    s3.download_file('panorama-ml-models-538269499906', 'onnx/model_int8.onnx', '/tmp/model.onnx')
    
    import onnxruntime as ort
    from transformers import AutoTokenizer
    
    session = ort.InferenceSession('/tmp/model.onnx')
    tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2', cache_dir='/tmp')
    model_loaded = True

def handler(event, context):
    load_model()
    
    def get_embedding(text):
        inputs = tokenizer(text, padding=True, truncation=True, max_length=128, return_tensors='np')
        outputs = session.run(None, {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        })
        embeddings = outputs[0][0]
        mask = inputs['attention_mask'][0]
        return np.mean(embeddings * mask.reshape(-1, 1), axis=0).tolist()
    
    with db_session() as db:
        techniques = db.query(MitreTechnique).filter(
            MitreTechnique.is_deprecated == False
        ).all()
        
        embeddings = {}
        for tech in techniques:
            text = f"{tech.technique_id}: {tech.name}. {tech.description[:500] if tech.description else ''}"
            embeddings[tech.technique_id] = get_embedding(text)
        
        s3.put_object(
            Bucket='panorama-ml-models-538269499906',
            Key='onnx/technique_embeddings.json',
            Body=json.dumps(embeddings)
        )
    
    return {'statusCode': 200, 'techniques': len(embeddings)}