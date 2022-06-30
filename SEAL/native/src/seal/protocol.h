#pragma once
#include "baseparty.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "util.h"
#include "poly.h"
#include <vector>
#include <iostream>
#include <unordered_map>
using namespace std;
using namespace seal;
using namespace seal::util;

class Protocol{
    private:
        unordered_map<uint64_t,BaseParty *> parties;
        unordered_map<uint64_t,bool> parties_status;
        map<string,map<uint64_t,vector<string>>> published_message;
        map<pair<uint64_t,uint64_t>,vector<string>> channels;
        uint64_t id_counter;
        uint64_t t_threshold;
        Poly secret_poly;
        SEALContext party_context;
        
    public:
        uint64_t server_party_id;
        Protocol(const SEALContext& ctx, uint64_t t):id_counter(0), parties_status({}), t_threshold(t), secret_poly(ctx), party_context(ctx){}
        void calculate_share(uint64_t party_id, string what_protocol="shamir"){
            if(what_protocol=="shamir"){
                calculate_shamir_share(is_first_t_party_online(), party_id);
            }
        }

        void decrypt(Ciphertext ctx, Plaintext& ptx){
            vector<int> indices = {};
            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    indices.push_back(i+1);
                    parties[i+1]->partial_decrypt(ctx);
                }
                if(indices.size()==t_threshold) break;
            } 
            auto lagr = lagrange(indices, t_threshold);
            parties[server_party_id]->gather_and_public_dec(lagr, indices);
            auto l = published_message["final_dec"][server_party_id].size();
            ptx = published_message["final_dec"][server_party_id][l-1];
            
        }
        

        void calculate_shamir_share(bool is_first_t_online, uint64_t party_id){
            BaseParty* new_party = parties[party_id];
            
            if(is_first_t_online){
                secret_poly = "0";
                secret_poly.to_double();
                for(size_t i = 1; i <= t_threshold; i++){
                    auto generator_party = parties[i];
                    new_party->update_private_share(generator_party->generate(party_id));
                    secret_poly.add_inplace(generator_party->generate(0));
                    secret_poly.to_int();
                    // cout << "secr" << secret_poly.to_string() << endl;
                }
                new_party->private_share_toint();
            }else{
                vector<int> indices = {};
                for(int i = 0; i < id_counter; i++){
                    if(parties_status[i+1]){
                        indices.push_back(i+1);
                        
                    }
                    if(indices.size()==t_threshold) break;
                } 
                sort(indices.begin(), indices.end());

                auto lagr = lagrange(indices, t_threshold, party_id); 
                for(size_t i = 0; i < t_threshold; i++){
                    new_party->update_private_share(parties[indices[i]]->share(), lagr[i]); 
                }
                new_party->private_share_toint();
            }
        }

        void generate_pk(){
            assign_server();
            parties[server_party_id]->generate_poly_A();
            vector<int> indices = {};
            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    indices.push_back(i+1);
                    parties[i+1]->generate_pki(server_party_id); 
                }
                if(indices.size()==t_threshold) break;
            }
            auto lagr = lagrange(indices, t_threshold);
            parties[server_party_id]->gather_and_public_pk(lagr, indices);
        }

        bool is_first_t_party_online(){
            for(size_t i = 1; i <= t_threshold; i++){
                if(!parties_status[i])
                    return false;
            }
            return true;
        }
        void assign_server(){
            server_party_id = 0;
            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    server_party_id = i+1;
                    parties[i+1]->is_server = true;
                    break;
                }
            }
        }
        uint64_t assign_new_party_id(BaseParty* new_party){
            if(new_party->registered()){return -1;}
            id_counter += 1;
            if(id_counter <= t_threshold){
                new_party->make_generator(t_threshold);
            }
            parties[id_counter]=new_party;
            parties_status[id_counter] = true;
            return id_counter;
        }
        void update_online_status(uint64_t party_id, bool connect){
            if(connect){
                parties_status[party_id] = true;
            }else{
                parties_status[party_id] = false;
            }
        }
        void update_publised_message(uint64_t party_id,string description, string message){
            published_message[description][party_id].push_back(message);
        }
        string public_message(string desc,int published_id, uint64_t msg_id = -1){ 
            if(published_id == -1){published_id = server_party_id;}
            if(msg_id==-1){
                msg_id = published_message[desc][published_id].size()-1;
            }
            return published_message[desc][published_id][msg_id];
        }
        void channel_read_request(uint64_t party_id, uint64_t sent_from, vector<string>& inbox){
            auto data = channels[make_pair(sent_from, party_id)];
            for (auto x: data){
                inbox.push_back(x);
            }
        }
        void channel_write_request(uint64_t party_id, uint64_t send_to, string message){
            channels[make_pair(party_id, send_to)].push_back(message);
        }
        
        void test(uint64_t id){
            if(parties_status[id])
                parties[id]->echo();
            else{
                std::cout << "The party is not online" << std::endl;
            }
            // Poly a(party_context, published_message["poly_A"][server_party_id][0]);
            
            // Poly test_poly(party_context);
            // // Poly x(party_context, secret_poly);
            // a.to_double();
            // secret_poly.to_int();
            // // x.to_int();
            // // x.to_double();
            // a.multiply_polynomial(secret_poly.data(), test_poly);
            // // cout << a.to_string() << "\t" << secret_poly.to_string() << endl;
            // test_poly.to_int();
            // test_poly.reduce_to_mod();
            // negate_poly_coeffmod(test_poly.data(), test_poly.coeff_count(), 0x7e00001, test_poly.data());
            // // cout << "PK:" <<test_poly.to_string() << endl;

            // // PublicKey pk;
            // Encryptor enc(party_context, test_poly.to_publickey(a));
            // Decryptor dec(party_context, secret_poly.to_secretkey());

            // Poly p(party_context,"2x^2 + 4");
            // Ciphertext ctx;
            // enc.encrypt(p,ctx);
            // dec.decrypt(ctx, p);
            // cout << "testttttt: " << p.to_string() << endl;
        }

};