import subprocess, os, argparse, time, sys

from trackers import *

from flask import Flask, request, send_file, Response, make_response


allowed_urls = [ # OPENFAAS URL : /function/{function_name} - microservices-demo URL : /online-butique/{function_name}
    "/online-butique/",
    "/online-butique/product/",
    "/online-butique/cart/",
    "/online-butique/setCurrency/",
    "/online-butique/logout/",
    "/online-butique/assistant/",
    "/online-butique/static/",
    "/online-butique/_healthz/",
    "/online-butique/product-meta/",
    "/online-butique/bot/",
    "/function/figlet/",
]

# client_list = {"7000": "asdfghc", "9088": "cvbnm", "2344": "hjklo", "5669": "qwerty"} 
# client_url = {"7000": "/function", "9088": "/notfunction", "2344": "/function/run", "5669": "/otherpath"}
# merkle=False
# token=False
# anon = True

app = Flask(__name__)


@app.route('/prove', methods=['POST'])
def upload_file():
    
    if args.test:
        start_time = time.time()
        out2 = [["Verification starts now", time.time()-start_time]]
    
    client_random = request.headers['Client-Random']
    file = request.files['proof']
    filename = f'files/proof{client_random}1.bin'
    file.save(filename)

    print("\n\n[+] Proof received!\n\n")

    if args.test:
        out2 = out2 + [["Proof received", time.time()-start_time]]

    jrun = ((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String pub ../middlebox/files/params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff {client_random} 1').split())        # LOCALHOST
    # jrun = ((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String pub ../middlebox/files/params.txt 0000d4d7508d0be25c2e3cb840b8ae34d32cff518c625b6a224c7a9894d35054ff {client_random} 1').split())    # TESTBED
    
    # FULL
    # jrun = ((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.Test_HTTP3_String_full pub ../middlebox/files/params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff {client_random} 1 300 100').split())        # LOCALHOST
    
    # POL
    # jrun = ((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.Test_HTTP3_String_POL pub ../middlebox/files/params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff {client_random} 1 100').split())        # LOCALHOST
                                                                                                                                                                     
    if args.test:
        try:
            (out_tmp, mem_tmp, cpu_time) = trackRun_cputime(jrun, 'xjsnark_verifyHTTP3_String', [start_time, 0])
            out = out2 + out_tmp
            mem = mem_tmp
        except subprocess.CalledProcessError:
            print(f'Wrong java parameters! {client_random} 1')

        try:
            (out_tmp, mem_tmp, cpu_time2) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/HTTP3_String.arith files/HTTP3_String_{client_random}1.pub.in verify {filename}').split(), 'libsnark_verifyHTTP3_String', [start_time, out[-1][2]])
            cpu_time +=cpu_time2
            out = out + out_tmp
            mem = mem + mem_tmp
        except subprocess.CalledProcessError:
            print(f'Wrong libsnark parameters! {client_random} 1')
            Response(status=401)

        os.makedirs(os.path.dirname(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/"), exist_ok=True)

        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/cputime_HTTP3_String_libsnark_verify.json", 'w', encoding='utf-8') as f:
            json.dump(cpu_time, f, ensure_ascii=False, indent=4)
        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/verify_HTTP3_String_output.json", 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=4)
        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/verify_HTTP3_String_memory.json", 'w', encoding='utf-8') as f:
            json.dump(mem, f, ensure_ascii=False, indent=4)

    else:
        try:
            subprocess.run(jrun).check_returncode()
        except subprocess.CalledProcessError:
            print("Wrong java parameters! " + client_random + " 1")
        
        try:
            subprocess.run((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/HTTP3_String.arith files/HTTP3_String_{client_random}1.pub.in verify {filename}').split()).check_returncode()

            # FULL
            # subprocess.run((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/Test_HTTP3_String_full.arith files/Test_HTTP3_String_full_{client_random}1.pub.in verify {filename}').split()).check_returncode()

            # POL
            # subprocess.run((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/Test_HTTP3_String_POL.arith files/Test_HTTP3_String_POL_{client_random}1.pub.in verify {filename}').split()).check_returncode()
        
        except subprocess.CalledProcessError:
            print("Wrong libsnark parameters! " + client_random + " 1")
            Response(status=403)

    print()
    return Response(status=200)


@app.route('/prover-key', methods=['GET'])
def return_file():
    response = make_response(send_file("files/provKey.bin", mimetype='application/octet-stream'))
    return response




if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="HTTP/3 middlebox")
    parser.add_argument(
        "-t", "--test", action="store_true", help="run test mode"
    )
    parser.add_argument(
        "-r", "--run", type=int, default=0, help="run number"
    )
    args = parser.parse_args()

    if not os.path.isfile('files/provKey.bin') or args.test:

        jrun = (('java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String pub ../middlebox/files/setup.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff circuitgen 1').split())
        lrun = (('../libsnark/build/libsnark/jsnark_interface/run_zkmb ../middlebox/files/HTTP3_String.arith setup').split())

        # FULL
        # jrun = (('java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.Test_HTTP3_String_full pub ../middlebox/files/setup.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff circuitgen 1 300 100').split())
        # lrun = (('../libsnark/build/libsnark/jsnark_interface/run_zkmb ../middlebox/files/Test_HTTP3_String_full.arith setup').split())

        # POL
        # jrun = (('java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.Test_HTTP3_String_POL pub ../middlebox/files/setup.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff circuitgen 1 100').split())
        # lrun = (('../libsnark/build/libsnark/jsnark_interface/run_zkmb ../middlebox/files/Test_HTTP3_String_POL.arith setup').split())

        if args.test:
            jname = "xjsnark_setup_HTTP3_String.json"
            
            os.makedirs(os.path.dirname(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/"), exist_ok=True)

            try:
                print("Running Java")
                start_time=time.time()
                (out_tmp, mem_tmp, cpu_time) = trackRun_cputime(jrun, jname, [start_time, 0])
                with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/cputime_HTTP3_String_java_pub.json", 'w', encoding='utf-8') as f:
                    json.dump(cpu_time, f, ensure_ascii=False, indent=4)
                out = out_tmp
                mem = mem_tmp
                subprocess.run(('rm files/HTTP3_String_circuitgen1.pub.in').split()).check_returncode()

            except subprocess.CalledProcessError:
                print("Wrong parameters, server not starting")
                exit()

            print("Running Libsnark")
            lname = 'libsnark_setup_HTTP3_String'
            (out_tmp, mem_tmp, cpu_time)=trackRun_cputime(lrun, lname, [start_time, out[-1][2]])
            out = out + out_tmp
            out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
            out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
            mem = mem + mem_tmp
            
            with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/cputime_HTTP3_String_libsnark_setup.json", 'w', encoding='utf-8') as f:
                json.dump(cpu_time, f, ensure_ascii=False, indent=4)
            with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/setup_HTTP3_String_output.json", 'w', encoding='utf-8') as f:
                json.dump(out, f, ensure_ascii=False, indent=4)
            with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/setup_HTTP3_String_memory.json", 'w', encoding='utf-8') as f:
                json.dump(mem, f, ensure_ascii=False, indent=4)

        else:
            try:
                subprocess.run(jrun).check_returncode()
            except subprocess.CalledProcessError:
                print("Wrong parameters, server not starting")
                exit()

            subprocess.run(lrun).check_returncode()
    
    print("\n\nGeneration done. Starting Flask Server\n")
    app.run(host='0.0.0.0', port=5001)