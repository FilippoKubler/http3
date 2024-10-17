import subprocess, psutil, time, json, threading, os
from pathlib import Path

exec_memory=[]
cpu_current_time = 0

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FUNCTIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# HTTP3 LEN

def test_http3_len(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    print('\n\n')
    print('~'*150)
    print('\nStarting HTTP3 LEN test . . .\n')

    folder = '/http3_len'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit} run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_req_{str(i)} 1 {str(i)} 100").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith files/{circuit}_run_req_{str(i)}1.in prove run_req_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith files/{circuit}_run_req_{str(i)}1.in verify files/proofrun_req_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_req_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding HTTP3 LEN test . . .\n')
    print('~'*150, '\n\n')


def test_http3_len_static(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE Static Implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting Static Implementation test . . .\n')

    folder = '/static_dynamic'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_static run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_req_static_{str(i)} 1 {str(i)} 100").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith files/{circuit}_static_run_req_static_{str(i)}1.in prove run_req_static_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith files/{circuit}_static_run_req_static_{str(i)}1.in verify files/proofrun_req_static_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_req_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding Static Implementation test . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def test_http3_len_full_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE FULL Descryption Implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting FULL Descryption Implementation tests . . .\n')

    folder = '/full_decryption'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_full run ../Tests/client_params_full.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_req_full_dec_{str(i)} 1 {str(i)} 100").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith files/{circuit}_full_run_req_full_dec_{str(i)}1.in prove run_req_full_dec_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith files/{circuit}_full_run_req_full_dec_{str(i)}1.in verify files/proofrun_req_full_dec_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_req_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding FULL Descryption Implementation tests . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    

def test_http3_len_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE Encryption part (TLSKeySchedule.quic_get1RTT_HS_new) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting Encryption tests . . .\n')

    folder = '/encryption'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_Encryption run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_enc_{str(i)} 1 {str(i)} 100").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Encryption.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Encryption.arith files/{circuit}_Encryption_run_enc_{str(i)}1.in prove run_enc_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Encryption.arith files/{circuit}_Encryption_run_enc_{str(i)}1.in verify files/proofrun_enc_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_enc_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding Encryption tests . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



# POLICY LEN

def test_policy_len(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    print('\n\n')
    print('~'*150)
    print('\nStarting POLICY LEN test . . .\n')

    folder = '/policy_len'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)
        
    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit} run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_pol_{str(i)} 1 300 {str(i)}").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith files/{circuit}_run_pol_{str(i)}1.in prove run_pol_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}.arith files/{circuit}_run_pol_{str(i)}1.in verify files/proofrun_pol_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_pol_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding POLICY LEN test . . .\n')
    print('~'*150, '\n\n')


def test_policy_len_static(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE Static Implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting Static Implementation test . . .\n')

    folder = '/static_dynamic'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_static run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_pol_static_{str(i)} 1 300 {str(i)}").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith files/{circuit}_static_run_pol_static_{str(i)}1.in prove run_pol_static_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_static.arith files/{circuit}_static_run_pol_static_{str(i)}1.in verify files/proofrun_pol_static_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_pol_static_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding Static Implementation test . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    

def test_policy_len_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i):
    
    # MEASURE POLICY LEN Descryption Implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting POLICY LEN Descryption Implementation tests . . .\n')

    folder = '/policy_decryption'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_POL run ../Tests/client_params.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_pol_dec_{str(i)} 1 {str(i)}").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_POL.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_POL.arith files/{circuit}_POL_run_pol_dec_{str(i)}1.in prove run_pol_dec_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_POL.arith files/{circuit}_POL_run_pol_dec_{str(i)}1.in verify files/proofrun_pol_dec{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_pol_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding POLICY LEN Descryption Implementation tests . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    

def test_policy_len_full_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE FULL Descryption Implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting FULL Descryption Implementation tests . . .\n')

    folder = '/full_decryption'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_full run ../Tests/client_params_full.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_pol_full_dec_{str(i)} 1 300 {str(i)}").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith files/{circuit}_full_run_pol_full_dec_{str(i)}1.in prove run_pol_full_dec_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_full.arith files/{circuit}_full_run_pol_full_dec_{str(i)}1.in verify files/proofrun_pol_full_dec_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_pol_full_dec_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding FULL Descryption Implementation tests . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    

def test_policy_len_match(pathj, pathls, pathlp, pathlv, path, circuit, num, i):

    # MEASURE Match part (LabelExtraction.firewall) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    print('\n\n')
    print('~'*150)
    print('\nStarting Match tests . . .\n')

    folder = '/match'
    Path(f'{path}{folder}').mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()

    (out, mem, cpu_time) = trackRun_cputime((f"java -Xmx6G -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.{circuit}_Match run ../Tests/client_params_match.txt 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff run_mat_{str(i)} 1 300 {str(i)} 1").split(), "", [start_time, 0])
    with open(pathj, 'a') as file:
        file.write(str(cpu_time) + '\n')
    print("Tot CPU Time: ",cpu_time)
    with open(f'{path}{folder}/output_java_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_java_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
    
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Match.arith setup').split(), "", [time.time(), 0])
    out +=[["PK Size", os.path.getsize('files/provKey.bin')]]
    out +=[["VK Size", os.path.getsize('files/veriKey.bin')]]
    with open(pathls, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_setup_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_setup_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Match.arith files/{circuit}_Match_run_mat_{str(i)}1.in prove run_mat_{str(i)} 1').split(), "", [time.time(), 0])
    with open(pathlp, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_prove_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_prove_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)
        
    (out, mem, cpu_time) = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/{circuit}_Match.arith files/{circuit}_Match_run_mat_{str(i)}1.in verify files/proofrun_mat_{str(i)}1.bin').split(), "", [time.time(), 0])
    with open(pathlv, 'a') as file:
        file.write(str(cpu_time) + '\n')
    with open(f'{path}{folder}/output_libsnark_verify_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=4)
    with open(f'{path}{folder}/memory_libsnark_verify_{circuit}_mat_{str(i)}_{str(num)}.json', 'w', encoding='utf-8') as f:
        json.dump(mem, f, ensure_ascii=False, indent=4)

    print('\nEnding Match tests . . .\n')
    print('~'*150, '\n\n')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def trackMem(popen, cputime):

    global cpu_time
    while popen.poll() is None:
        proc = psutil.Process(popen.pid)
        java_memory_usage = proc.memory_full_info().uss / 1000000
        #print(proc.cpu_times())
        cpu_time = proc.cpu_times().user + proc.cpu_times().system
        #print(cpu_time)
        #print(java_memory_usage)

        if cputime:
            exec_memory.append([java_memory_usage, time.time()-current_time, cpu_time+cpu_current_time])
        else:
            exec_memory.append([java_memory_usage, time.time()-current_time])
        #print(exec_memory[-1][1])
        time.sleep(1)
    popen.wait()
    print("Process finished")



#df = pandas.read_json('data.json')
def trackRun(cmd, outname, call_time):
    exec_output = []
    global exec_memory
    global cpu_time
    exec_memory = []
    #print(call_time)
    global current_time
    current_time = call_time
    #exec_memory=[]
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    proc = psutil.Process(popen.pid)
    print("Starting ",cmd)
    thread = threading.Thread(target=trackMem, args=[popen, False])
    thread.start()
    for line in iter(popen.stdout.readline, ""):
        #print(line)

        instant = time.time()-current_time
        try:
            cpu_time = proc.cpu_times().user + proc.cpu_times().system
            java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
            exec_memory.append([java_memory_usage, instant, cpu_time + cpu_current_time])
            #print(java_memory_usage)
            exec_output.append([line, instant, cpu_time + cpu_current_time])
        except psutil.NoSuchProcess:
            print("\n WARNING: Process already ended\n")
            pass
            
    thread.join()
    #print("done, ", exec_memory)
    exec_output.append(["Done", time.time()-current_time, cpu_time + cpu_current_time])

    '''
    current_time=time.time()
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    print("Executing memory profiling run...")
    while popen.poll() is None:
        java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
        print(java_memory_usage)
        exec_memory.append([java_memory_usage, time.time()-current_time])
        time.sleep(1)
    popen.wait()
    '''
    #with open(outname+"_output.json", 'w', encoding='utf-8') as f:
    #    json.dump(exec_output, f, ensure_ascii=False, indent=4)
    #with open(outname+"_memory.json", 'w', encoding='utf-8') as f:
    #    json.dump(exec_memory, f, ensure_ascii=False, indent=4)
    return(exec_output, exec_memory, cpu_time)



def trackRun_cputime(cmd, outname, call_time):
    exec_output = []
    global exec_memory
    global cpu_time
    exec_memory = []
    #print(call_time)
    global current_time
    global cpu_current_time
    current_time = call_time[0]
    cpu_current_time = call_time[1]
    #exec_memory=[]
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    proc = psutil.Process(popen.pid)
    print("Starting ",cmd)
    thread = threading.Thread(target=trackMem, args=[popen, True])
    thread.start()
    for line in iter(popen.stdout.readline, ""):
        #print(line)
        instant = time.time()-current_time
        try:
            cpu_time = proc.cpu_times().user + proc.cpu_times().system
            java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
            exec_memory.append([java_memory_usage, instant, cpu_time+cpu_current_time])
            #print(java_memory_usage)
            exec_output.append([line, instant, cpu_time+cpu_current_time])
        except psutil.NoSuchProcess:
            print("\n\n WARNING!!!!!!!!!! Process already ended\n\n")
            pass
            
    thread.join()
    #print("done, ", exec_memory)
    exec_output.append(["Done", time.time()-current_time, cpu_time+cpu_current_time])

    '''
    current_time=time.time()
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    print("Executing memory profiling run...")
    while popen.poll() is None:
        java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
        print(java_memory_usage)
        exec_memory.append([java_memory_usage, time.time()-current_time])
        time.sleep(1)
    popen.wait()
    '''
    #with open(outname+"_output.json", 'w', encoding='utf-8') as f:
    #    json.dump(exec_output, f, ensure_ascii=False, indent=4)
    #with open(outname+"_memory.json", 'w', encoding='utf-8') as f:
    #    json.dump(exec_memory, f, ensure_ascii=False, indent=4)
    return (exec_output, exec_memory, cpu_time)



def run_looped_tests_string(circuit, num):
    path = "../Tests/outputs/"+circuit+"/run"+str(num)
    
    # CREATE FOLDERS
    os.makedirs(os.path.dirname(path+"/output"), exist_ok=True)
    os.makedirs(os.path.dirname(path+"/memory"), exist_ok=True)
    
    # CREATE FILES
    pathj = f'{path}/cputimes_java_{circuit}_{str(num)}.txt'
    if os.path.isfile(pathj) and os.stat(pathj).st_size != 0:
        with open(pathj, 'w') as file:
            file.truncate()
    else:
        with open(pathj, 'w') as file:
            pass
    pathls = f'{path}/cputimes_libsnark_setup_{circuit}_{str(num)}.txt'
    if os.path.isfile(pathls) and os.stat(pathls).st_size != 0:
        with open(pathls, 'w') as file:
            file.truncate()
    else:
        with open(pathls, 'w') as file:
            pass
    pathlp = f'{path}/cputimes_libsnark_prove_{circuit}_{str(num)}.txt'
    if os.path.isfile(pathlp) and os.stat(pathlp).st_size != 0:
        with open(pathlp, 'w') as file:
            file.truncate()
    else:
        with open(pathlp, 'w') as file:
            pass
    pathlv = f'{path}/cputimes_libsnark_verify_{circuit}_{str(num)}.txt'
    if os.path.isfile(pathlv) and os.stat(pathlv).st_size != 0:
        with open(pathlv, 'w') as file:
            file.truncate()
    else:
        with open(pathlv, 'w') as file:
            pass
    

    # MEASURE MAX_HTTP3_LEN
    print('\n\n')
    print('~'*150)
    print('\nStarting MAX_HTTP3_LEN tests . . .\n')
    for i in [150, 300, 450, 600, 800, 1000, 1500, 2000]: # 100 troppo basso per la richiesta utilizzata

        test_http3_len(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

        test_http3_len_static(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

        test_http3_len_full_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i)
        
        test_http3_len_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i)
        
    print('\nEnding MAX_HTTP3_LEN tests . . .\n')
    print('~'*150, '\n\n')


    # MEASURE MAX_POLICY_LEN
    print('\n\n')
    print('~'*150)
    print('\nStarting MAX_POLICY_LEN tests . . .\n')
    for i in [30, 40, 50, 60, 70, 80, 90, 100]: # Minimum path size = /function/a (20 troppo basso per la Policy utilizzata, la quale è di 30 bytes)

        test_policy_len(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

        test_policy_len_static(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

        test_policy_len_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

        test_policy_len_full_decryption(pathj, pathls, pathlp, pathlv, path, circuit, num, i)
        
        test_policy_len_match(pathj, pathls, pathlp, pathlv, path, circuit, num, i)

    print('\nEnding MAX_POLICY_LEN tests . . .\n')
    print('~'*150, '\n\n')


    
if __name__=='__main__':
    for i in range(22, 23):
        print('\nSTARTING RUN', i, '\n')
        run_looped_tests_string('Test_HTTP3_String', i)