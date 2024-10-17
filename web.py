from prometheus_client import start_http_server, Gauge, generate_latest
from flask import Flask, jsonify, request, Response
import base64
import time
import fw
from waitress import serve



# Create a single gauge metric with labels
data_gauge = Gauge('pat_pool', 'pat_pool', ['protocol', 'interface','ip','range_start','range_end'])


def update_metrics(ipaddress,username,password):    
    print(f"Firewall:{ipaddress}")
    firewall=fw.firewall(username,password)
    nat_data=firewall.getNatPool(ipaddress)
    for entry in nat_data:
        data_gauge.labels(protocol=entry['protocol'], interface=entry['interface'],ip=entry['ip'],range_start=entry['range_start'],range_end=entry['range_end']).set(entry['size'])
         


# Flask app
app = Flask(__name__)


def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})




def requires_auth(f):
    def decorated(*args, **kwargs):
        auth = request.authorization
        # if not auth or not check_auth(auth.username, auth.password):
        if not auth:
            return authenticate()
        return f(*args, **kwargs)
    return decorated

#set target ip  variable = target=<ip>
@app.route('/metrics', methods=['GET'])
@requires_auth
def metrics():
    # check that this is an ip address and we can connect to on on port 22
    target = request.args.get('target')
    auth = request.headers.get('Authorization')
    username, password = base64.b64decode(auth.split(' ')[1]).decode('utf-8').split(':')
    try:
        update_metrics(target,username,password)
    except Exception as e:
        print(e)
        return jsonify({"error": e}), 400

    return Response(generate_latest(), mimetype='text/plain')

if __name__ == '__main__':
    ipaddress="0.0.0.0"
    port=3000
    print(f"Server running, ip:{ipaddress}:{port}")
    serve(app, host=ipaddress, port=port)
    