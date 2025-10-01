# lambda-functions/pano-compute-embeddings/lambda_function.py
import json
import boto3
import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer
from panorama_datamodel import db_session
from panorama_datamodel.models import MitreTechnique

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # Download ONNX model
    s3.download_file(
        'panorama-ml-models-538269499906', 
        'onnx/model_int8.onnx', 
        '/tmp/model.onnx'
    )
    
    session = ort.InferenceSession('/tmp/model.onnx')
    tokenizer = AutoTokenizer.from_pretrained(
        'sentence-transformers/all-MiniLM-L6-v2',
        cache_dir='/tmp'
    )
    
    with db_session() as db:
        # Only active techniques
        techniques = db.query(MitreTechnique).filter(
            MitreTechnique.is_deprecated == False,
            MitreTechnique.revoked == False
        ).all()
        
        embeddings = {}
        for tech in techniques:
            text = f"{tech.technique_id}: {tech.name}. {tech.description[:500] if tech.description else ''}"
            
            inputs = tokenizer(text, padding=True, truncation=True, max_length=128, return_tensors='np')
            outputs = session.run(None, {
                'input_ids': inputs['input_ids'],
                'attention_mask': inputs['attention_mask']
            })
            
            # Mean pooling
            emb = outputs[0][0]
            mask = inputs['attention_mask'][0]
            mask_expanded = np.expand_dims(mask, -1)
            sum_embeddings = np.sum(emb * mask_expanded, axis=0)
            sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
            embeddings[tech.technique_id] = (sum_embeddings / sum_mask).tolist()
        
        # Upload embeddings
        s3.put_object(
            Bucket='panorama-ml-models-538269499906',
            Key='onnx/technique_embeddings.json',
            Body=json.dumps(embeddings)
        )
    
    return {
        'statusCode': 200,
        'techniques': len(embeddings)
    }