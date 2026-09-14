"""Opt-in synthetic probe; prints usage, never private capture content."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import llm_client
from test_llm import payload

original = llm_client.urllib.request.build_opener
class Probe:
    def __init__(self, opener): self.opener = opener
    def open(self, request, **kwargs):
        body = json.loads(request.data)
        if len(sys.argv) > 1:
            body['max_tokens'] = int(sys.argv[1])
        response = self.opener.open(llm_client.urllib.request.Request(request.full_url,
            data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}), **kwargs)
        raw = response.read()
        response.close()
        parsed = json.loads(raw)
        choice = parsed.get('choices', [{}])[0]
        msg = choice.get('message', {})
        print(json.dumps({'usage': parsed.get('usage'), 'finish_reason': choice.get('finish_reason'),
              'content_chars': len(msg.get('content', '')), 'reasoning_chars': len(msg.get('reasoning_content', ''))}), flush=True)
        print('visible content:', msg.get('content', '')[:1500], flush=True)
        import io
        return io.BytesIO(raw)
llm_client.urllib.request.build_opener = lambda *args: Probe(original(*args))
print(llm_client.explain(payload())['answer']['summary'])
