import os
import re
import requests
import logging
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=['*'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABRICKS_HOST = os.getenv('DATABRICKS_HOST', '').rstrip('/')
DATABRICKS_TOKEN = os.getenv('DATABRICKS_TOKEN', '')
AGENT_ENDPOINT = os.getenv('AGENT_ENDPOINT', 'mas-44d28858-endpoint')

PII_PATTERNS = [
    r'\b(show|give|return|get|pull)\b.{0,30}\b(name|email|address|phone|ssn|date of birth)\b',
    r'\braw (record|data|pii|personal)\b',
    r'\bindividual.{0,20}(record|profile)\b',
]

RESTRICTED = [
    {'p': r'\b(race|ethnicity|racial|ethnic)\b', 'f': 'R5', 'm': 'Ethnicity data requires regulatory credentialing.'},
    {'p': r'\b(insert|update|delete|drop|truncate|write|modify)\b', 'f': 'WRITE', 'm': 'This portal is strictly read-only.'},
]

def check_security(query):
    if len(query) > 600:
        return {'blocked': True, 'msg': 'Query too long.'}
    for p in PII_PATTERNS:
        if re.search(p, query, re.IGNORECASE):
            return {'blocked': True, 'msg': 'This portal returns aggregated data only.'}
    for r in RESTRICTED:
        if re.search(r['p'], query, re.IGNORECASE):
            if r['f'] == 'WRITE':
                return {'blocked': True, 'msg': r['m']}
            return {'flagged': True, 'flag': r['f'], 'msg': r['m']}
    return {'safe': True}

@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'index.html')
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(content, mimetype='text/html')
    except Exception as e:
        logger.error('HTML read error: ' + str(e))
        return Response('<h1>InfoBase Portal</h1><p>Error loading UI: ' + str(e) + '</p>', mimetype='text/html')

@app.route('/query', methods=['POST'])
def query():
    data = request.get_json(silent=True)
    if not data or not data.get('query'):
        return jsonify({'error': 'No query provided'}), 400

    if not DATABRICKS_TOKEN or not DATABRICKS_HOST:
        return jsonify({'error': 'Agent not configured.'}), 503

    query_text = str(data.get('query', ''))[:600]
    conversation = data.get('messages', [])

    sec = check_security(query_text)
    if sec.get('blocked'):
        return jsonify({'blocked': True, 'message': sec['msg']})

    input_messages = []
    for msg in conversation[-10:]:
        role = msg.get('role', 'user')
        content = str(msg.get('content', ''))[:1000]
        if role in ('user', 'assistant'):
            input_messages.append({'role': role, 'content': content})
    input_messages.append({'role': 'user', 'content': query_text})

    try:
        url = DATABRICKS_HOST + '/serving-endpoints/' + AGENT_ENDPOINT + '/invocations'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + DATABRICKS_TOKEN
        }
        payload = {'input': input_messages}
        resp = requests.post(url, json=payload, headers=headers, timeout=120)
        resp.raise_for_status()
        result = resp.json()

        reply = ''
        if 'choices' in result and result['choices']:
            reply = result['choices'][0].get('message', {}).get('content', '')
        elif 'output' in result:
            reply = str(result['output'])
        elif 'predictions' in result and result['predictions']:
            pred = result['predictions'][0]
            if isinstance(pred, dict):
                msgs = pred.get('messages', [])
                reply = msgs[-1].get('content', '') if msgs else str(pred)
            else:
                reply = str(pred)
        else:
            reply = str(result)

        return jsonify({'success': True, 'reply': reply, 'flagged': sec.get('flagged', False)})

    except requests.exceptions.Timeout:
        return jsonify({'error': 'The agent took too long. Please try again.'}), 504
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else 500
        if status in (401, 403):
            return jsonify({'error': 'Authentication failed.'}), 503
        return jsonify({'error': 'Agent temporarily unavailable.'}), 503
    except Exception as e:
        logger.error('Error: ' + str(e)[:100])
        return jsonify({'error': 'Something went wrong. Please try again.'}), 500

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'agent': AGENT_ENDPOINT,
        'host_set': bool(DATABRICKS_HOST),
        'token_set': bool(DATABRICKS_TOKEN)
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
