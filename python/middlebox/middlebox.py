import subprocess, os
from flask import Flask, request, send_file, Response, make_response

client_list = {"7000": "asdfghc", "9088": "cvbnm", "2344": "hjklo", "5669": "qwerty"} 
client_url = {"7000": "/function", "9088": "/notfunction", "2344": "/function/run", "5669": "/otherpath"}
allowed_urls = ["/function/figlet", "/function/test"]

circuit = ""
url = ""
merkle=False
token=False
anon = True

app = Flask(__name__)


@app.route('/prove', methods=['POST'])
def upload_file():
    
    client_random = request.headers['Client-Random']
    file = request.files['proof']
    filename = 'files/proof'+client_random+'1.bin'
    file.save(filename)

    print("\n\n[+] Proof received!\n\n")
    
    jrun = ((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String pub ../middlebox/files/params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff {client_random} 1').split())

    try:
        subprocess.run(jrun).check_returncode()
    except subprocess.CalledProcessError:
        print("Wrong java parameters! " + client_random + " 1")
    
    try:
        subprocess.run((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/HTTP3_String.arith files/HTTP3_String_{client_random}1.pub.in verify files/proof{client_random}1.bin').split()).check_returncode()
    except subprocess.CalledProcessError:
        print("Wrong libsnark parameters! " + client_random + " 1")
        Response(status=403)

    return Response(status=200)


@app.route('/prover-key', methods=['GET'])
def return_file():
    response = make_response(send_file("files/provKey.bin", mimetype='application/octet-stream'))
    return response
        

@app.route('/parameters', methods=['GET'])
def return_params():
    if(request.headers['Client-ID'] in client_list):
        print(request.headers['Client-ID'])
        response = Response(status=200)
        response.headers['Allowed-URL'] = client_url[request.headers['Client-ID']]

        return response
    else:
        return Response(status=401)
        

@app.route('/url-list', methods=['GET'])
def return_urllist():
    if(request.headers['Client-ID'] in client_list):
        print(request.headers['Client-ID'])
        if(anon):
            #TODO: generate tree and root file
            response = make_response(send_file("files/anon_tree.txt", mimetype='text/plain'))
        else:
            response = make_response(send_file("files/allowlist.txt", mimetype='text/plain'))
        return response
    else:
        return Response(status=401)



if __name__ == '__main__':

    if not os.path.isfile('files/provKey.bin'):
        jrun = (('java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String pub ../middlebox/files/setup.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff circuitgen 1').split())
        lrun = (('../libsnark/build/libsnark/jsnark_interface/run_zkmb ../middlebox/files/HTTP3_String.arith setup').split())
        try:
            subprocess.run(jrun).check_returncode()
        except subprocess.CalledProcessError:
            print("Wrong parameters, server not starting")
            exit()

        subprocess.run(lrun).check_returncode()
    
    print("\n\nGeneration done. Starting Flask Server\n")
    app.run(host='0.0.0.0', port=5001)