from seal import *
import time
import numpy as np


parms = EncryptionParameters(scheme_type.bfv)
poly_modulus_degree = 2048
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(2048))
parms.set_plain_modulus(2**19)
context = SEALContext(parms)


def numpy_to_string(np_array):
    x = np.zeros([poly_modulus_degree])
    x[:len(np_array)] = np_array
    res = ""
    for i, v in enumerate(x[::-1]):
        i = poly_modulus_degree-i-1
        if i != 0 and v > 0:
            res += f"{hex(int(v))}"[2:]+f"x^{i} + "
        elif i==0:
            res += f"{hex(int(v))}"[2:]
    return res
def string_to_numpy(hex_poly):
    elem = hex_poly.split(" + ")
    if('x' not in elem[-1]):
        elem[-1] += "x^0"
    values = [int("0x"+e.split("x")[0],16) for e in elem]
    keys = [int(e.split("x^")[1]) for e in elem]
    results = np.zeros([poly_modulus_degree],dtype=int)
    for k,v in zip(keys, values):
        results[k] = v
    return results

def secure_add(a, b, party_a, party_b, proto, evaluator):
    ptx_a = Plaintext(numpy_to_string(a))
    ptx_b = Plaintext(numpy_to_string(b))
    ctx_a = party_a.encrypt(ptx_a)
    ctx_b = party_b.encrypt(ptx_b)
    ctx_res = evaluator.add(ctx_a, ctx_b)
    dec = proto.decrypt(ctx_res)
    return string_to_numpy(dec.to_string())

n = 100
t = 20
proto = Protocol(context,t)
eval = Evaluator(context)
parties = []
for i in range(n):
    p = Party(context)
    parties.append(p)
    p.register(proto)
for i in range(n):
    proto.calculate_share(i+1)
proto.generate_pk()
parties[1].update_pk()
x = np.random.randint(0,65534,poly_modulus_degree)
y = 65534-x# np.array([5,4,3,2,1])
t = time.time()
z = secure_add(x,y,parties[2], parties[5], proto, eval)
print("Add time: ", time.time()-t)
print(z[:5])

import torch.nn as nn

model = nn.Sequential(
    nn.Linear(784, 128),
    nn.Linear(128, 256),
    nn.Linear(256, 10)
)
def get_n_params(model):
    pp=0
    for p in list(model.parameters()):
        print(p.size())
        nnn=1
        for s in list(p.size()):
            nnn = nnn*s
        pp += nnn
    return pp
print(get_n_params(model))