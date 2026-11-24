import os
from backend import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[SECURITY] SentinelShield Adaptive Backend active on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
