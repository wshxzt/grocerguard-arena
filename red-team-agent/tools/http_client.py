"""HTTP client for attacking the target application."""
import json
import requests

TIMEOUT = 15


def http_request(method, url, headers=None, body=None, cookies=None, follow_redirects=True):
    try:
        kwargs = {
            'headers':         headers or {},
            'cookies':         cookies or {},
            'allow_redirects': follow_redirects,
            'timeout':         TIMEOUT,
        }
        if body:
            kwargs['data'] = body

        resp = requests.request(method.upper(), url, **kwargs)

        return {
            'status_code': resp.status_code,
            'headers':     dict(resp.headers),
            'body':        resp.text[:8000],
            'final_url':   resp.url,
            'cookies':     dict(resp.cookies),
        }
    except Exception as e:
        return {'error': str(e)}
