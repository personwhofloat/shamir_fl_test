#pragma once
#include "poly.h"
class BaseParty{
public:
    bool is_server;
    virtual void echo()=0;
    virtual void make_generator(int t)=0;
    virtual bool registered()=0;
    virtual Poly generate(int64_t req)=0;
    virtual void update_private_share(Poly poly, double multiplicand=1)=0;
    virtual void private_share_toint()=0;
    virtual Poly& share()=0;
    virtual void generate_poly_A()=0;
    virtual void generate_pki(uint64_t party_id)=0;
    virtual void gather_and_public_pk(vector<double_t> lg, vector<int> id)=0;
    virtual void partial_decrypt(Ciphertext ctx)=0;
    virtual void gather_and_public_dec(vector<double_t> lagr, vector<int> indices)=0;
    // virtual void generate_poly_A(Protocol& proto) = 0;
};