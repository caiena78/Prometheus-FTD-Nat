from prometheus_client import Gauge, generate_latest,CollectorRegistry
from flask import Flask, jsonify, request, Response
import base64
import time
import fw
from waitress import serve
from netmiko import NetMikoAuthenticationException




# Create a single gauge metric with labels



def update_metrics(ipaddress,username,password,registry):   
     
    data_gauge = Gauge('pat_pool', 'pat_pool', ['protocol', 'interface','ip','range_start','range_end'],registry=registry)       
    print(f"Firewall:{ipaddress}")
    firewall=fw.firewall(username,password)
    nat_data=firewall.getNatPool(ipaddress)
    for entry in nat_data:
        data_gauge.labels(protocol=entry['protocol'], interface=entry['interface'],ip=entry['ip'],range_start=entry['range_start'],range_end=entry['range_end']).set(entry['size'])       
    print(f"Finished updated Firewall:{ipaddress}")   
    


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
    target = request.args.get('target')
    auth = request.headers.get('Authorization')
    username, password = base64.b64decode(auth.split(' ')[1]).decode('utf-8').split(':')
    registry = CollectorRegistry()   
    prob_success=Gauge('probe_success','prob_success',registry=registry)   
    try:
       update_metrics(target,username,password,registry)
       prob_success.set(1)
    except NetMikoAuthenticationException:
        print("login failed")
        return authenticate()
    except Exception as e:
        print(e)
        prob_success.set(0)
        # return jsonify({"error": e}), 400    
    
    return Response(generate_latest(registry), mimetype='text/plain')

if __name__ == '__main__':
    ipaddress="0.0.0.0"
    port=3000
    print(f"Server running, ip:{ipaddress}:{port}")
    serve(app, host=ipaddress, port=port)
    