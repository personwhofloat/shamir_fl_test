#pragma once
#include "protocol.h"
// #include "party.h"
#include "zeroshare.h"
#include "metapoly.h"
#include "baseparty.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "partial_decryptor.h"
class Party: public BaseParty{
private:
    SEALContext party_context;
    MetaPoly share_generator;
    Poly private_share;
    uint64_t party_id;
    vector<string> inbox;
    bool has_registered;
    bool is_pk_fetched;
    bool is_decryptor_generated;
    Protocol *proto;
    PublicKey pk;
    // Poly dummy_message;
    Encryptor* encryptor;
    PartialDecryptor* decryptor;
    
public:
    bool is_server;
    Party(const SEALContext& ctx): party_context(ctx),share_generator(ctx, {}), private_share(ctx), has_registered(false),is_decryptor_generated(false), is_pk_fetched(false), inbox({}),  is_server(false){}
    void register_party(Protocol& protocol){
        
        uint64_t proposed_id = protocol.assign_new_party_id(this);
        if(proposed_id != -1){
            party_id = proposed_id; // new party is created
            has_registered = true;
        }   
        proto = &protocol;
    }
    void disconnect(){
        proto->update_online_status(party_id, false);
    }
    void connect(){
        proto->update_online_status(party_id, true);
    }

    void broadcast(string desc, Poly message){
        string str;
        str = message.to_string();
        proto->update_publised_message(party_id, desc, str);
    }
    void send(uint64_t to_party_id, string message){
        proto->channel_write_request(party_id, to_party_id, message);
    }
    void receive(uint64_t from_party_id){
        proto->channel_read_request(party_id, from_party_id, inbox);
    }
    string retrieve_from_broadcast(string desc, uint64_t server_id){
        // proto->public_message(desc, server_id);
        string msg = proto->public_message(desc, server_id);
        return msg;
    }

    void generate_poly_A(){
        auto &context_data = *party_context.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_keyz;
        encrypt_zero_symmetric(private_share.to_secretkey(), party_context, context_data.parms_id(), true, false, public_keyz.data());
        
        Poly a = Poly::get_random_poly(party_context, UniformRandomGeneratorFactory::DefaultFactory()->create());//Poly(party_context, "FFF7FFF4x^3 + FFFFFFF4x^2 + FFFFFFF4x^1 + FFFFFFF4");//Poly(party_context);//
        // for(size_t i = 0; i < coeff_count; i++)
        //     a.data()[i] = public_keyz.data().data()[i];
        broadcast("poly_A", a);
    }
    void generate_pki(uint64_t server_id){
        Poly *a;//(party_context);
        string msg = retrieve_from_broadcast("poly_A", server_id);
        a = new Poly(party_context,msg);
        Poly public_key(party_context);
        
        a->multiply_polynomial(private_share.data(), public_key);
        // negate_poly_coeffmod()
        public_key.to_int();
        // cout << public_key.to_string() << "\t" << a->to_string() << "\t" << private_share.to_string() << endl;
        broadcast("pki", public_key);
        
        // cout << "aa" << endl;
    }

    void update_pk(){
        if(is_pk_fetched) {
            Poly pk_poly(party_context, retrieve_from_broadcast("public_key",-1));
            // cout << "pk:" << pk_poly.to_string() << endl;
            return;
        }

        Poly pk_poly(party_context, retrieve_from_broadcast("public_key",-1));
        
        Poly a(party_context, retrieve_from_broadcast("poly_A",-1));
        pk_poly.reduce_to_mod();
        a.reduce_to_mod();
        
        encryptor = new Encryptor(party_context, pk_poly.to_publickey(a));
        is_pk_fetched = true;
    }

    void encrypt(Plaintext ptx, Ciphertext& ctx){
        update_pk();
        encryptor->encrypt(ptx, ctx);
    }

    void partial_decrypt(Ciphertext ctx){
        Poly ptx(party_context);
        if(!is_decryptor_generated){
            decryptor = new PartialDecryptor(party_context, private_share.to_secretkey());
            is_decryptor_generated=true;
        }
        decryptor->bfv_decrypt(ctx, ptx);
        // ptx.to_int();
        broadcast("ptxi", ptx);
    }

    void gather_and_public_dec(vector<double_t> lagr, vector<int> indices){
        Poly ptx(party_context);
        for(size_t i = 0; i < indices.size(); i++){
            int id = indices[i];
            double_t weight = lagr[i];
            Poly ptxi(party_context, retrieve_from_broadcast("ptxi", id));
            // cout << id << ": "<< ptxi.to_string() << endl;
            ptx.add_the_multiply_inplace_double(ptxi, weight);
        }
        // ptx.to_int();
        
        decryptor->post_process(ptx);
        broadcast("final_dec", ptx);
    }


    void gather_and_public_pk(vector<double_t> lagr, vector<int> indices){
        cout << "GATHERING" << endl;
        Poly public_key(party_context);
        for(size_t i = 0; i < indices.size(); i++){
            int id = indices[i];
            double_t weight = lagr[i];
            Poly pki(party_context,retrieve_from_broadcast("pki", id));
            // cout << pki.to_string() << endl;
            public_key.add_the_multiply_inplace_double(pki, weight);
        }
        public_key.to_int();
        public_key.reduce_to_mod();
        public_key.negate();
        // cout << public_key.to_string() << endl;
        broadcast("public_key", public_key);
    }

    Poly generate(int64_t requested_id){
        Poly result = share_generator(requested_id);
        return result;
    }
    void update_private_share(Poly poly, double multiplicand=1){
        if(multiplicand==1){
            private_share.add_inplace(poly);
        }else{
            private_share.add_the_multiply_inplace_double(poly, multiplicand);
        }
    }
    void private_share_toint(){
        private_share.to_int();
        private_share.reduce_to_mod();
    }

    void make_generator(int t_threshold){
        auto &context_data = *party_context.key_context_data();
        auto &parms = context_data.parms();
        vector<Poly *> list_to_make_metapoly;
        for(size_t i = 0; i < t_threshold; i++){
            Poly* new_poly = new Poly(Poly::get_random_poly(party_context, parms.random_generator()->create(), "ternary"));// new Poly(Poly::ones(party_context));//
            list_to_make_metapoly.push_back(new_poly);
        }
        share_generator = list_to_make_metapoly;
    }

    void echo(){
        cout << "Hello world i am party " << party_id << endl;
        // cout << "My share: " << private_share.to_string() << endl;
    }
    bool registered(){
        return has_registered;
    }

    Poly& share(){
        return private_share;
    }
};