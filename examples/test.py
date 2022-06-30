from seal import *
import time
import numpy as np


parms = EncryptionParameters(scheme_type.bfv)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(2048))
parms.set_plain_modulus(2**19)
context = SEALContext(parms)


def numpy_to_string(np_array):
    x = np.zeros([poly_modulus_degree])
    # x[:len(np_array)].shape
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

def secure_add(a, b, party_a, party_b, evaluator):
    ptx_a = Plaintext(numpy_to_string(a))
    ptx_b = Plaintext(numpy_to_string(b))
    # print(ptx_a.to_string())
    ctx_a = party_a.encrypt(ptx_a)
    ctx_b = party_b.encrypt(ptx_b)
    ctx_res = evaluator.add(ctx_a, ctx_b)
    return ctx_res


# ctx = SEALContext()
party = Party(context)
party2 = Party(context)
party3 = Party(context)
party4 = Party(context)
party5 = Party(context)
party6 = Party(context)
proto = Protocol(context, 5)
party.register(proto)
party2.register(proto)
party3.register(proto)
party4.register(proto)
party5.register(proto)
party6.register(proto)
proto.test(1)
proto.calculate_share(1)
proto.calculate_share(2)
proto.calculate_share(3)
proto.calculate_share(4)
proto.calculate_share(5)
proto.calculate_share(6)

party2.disconnect()
proto.generate_pk()

# ctx = Ciphertext()
# ctx2 = Ciphertext()
ptx = Plaintext("1021x^1023 + 2")
ptx2 = Plaintext("65534x^2 + 3")
# ptx = 

party.update_pk()
party2.update_pk()

t = time.time()
ctx=party.encrypt(ptx)
print("enc time: ", time.time()-t)
ctx2= party2.encrypt(ptx2)

eval = Evaluator(context)
t = time.time()
ctx3 = eval.add(ctx, ctx2)
print("eval time: ", time.time() -t)

t = time.time()
ptx3 = proto.decrypt(ctx3)
print("dec time: ", time.time()-t)

t = time.time()
dat1 = np.random.randint(0,10000,poly_modulus_degree)

dat2 = 100000-dat1
p1 = numpy_to_string(dat1)
p2 = numpy_to_string(dat2)
p1, p2 = Plaintext(p1), Plaintext(p2)
print(p1.to_string())
print(p2.to_string())
c1 = party.encrypt(p1)
c2 = party2.encrypt(p2)
c3 = eval.add(c1, c2)
# ctx = secure_add(dat1, dat2, party, party3, eval)
p = proto.decrypt(c3)

print(string_to_numpy(p.to_string())[:10])
print("One addition time: ", time.time()-t)