#pragma once
#include "seal/secretkey.h"
#include "seal/plaintext.h"
#include "seal/dynarray.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"

using namespace seal;
using namespace std;
using namespace seal::util;


class Poly: public Plaintext{
public:
    Poly(const SEALContext &context,MemoryPoolHandle pool = MemoryManager::GetPool()): 
    Plaintext(pool),
    context_(context){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        coeff_mod_ = parms.coeff_modulus();
        coeff_mod_size_ = coeff_mod_.size();
        poly_coeff_count_ = parms.poly_modulus_degree(); 
        reserve(poly_coeff_count_*coeff_mod_size_);
        resize(poly_coeff_count_*coeff_mod_size_);
        to_double();
        
    }
    Poly(const SEALContext &context, const string hex_poly):
    Poly(context){
        operator=(hex_poly);
        to_double();
    }
    Poly(const SEALContext &context, Poly& poly):
    Poly(context){
        operator=(poly);
        to_double();
    }
    Plaintext& operator=(const string hex_poly){
        Plaintext::operator=(hex_poly);
        to_double();
        return *this;   
    }
    Plaintext& operator=(Plaintext& ptx){
        return Plaintext::operator=(ptx);
    }

    void add_inplace(Poly other){   
        auto dat = data();
        auto other_data = other.data(); 
        auto size = coeff_count();
        auto size_other = other.coeff_count();
        auto max_size = max(size, size_other);
        if(size > size_other){
            auto max_size = size;
            auto min_size = size_other;
            other.reserve_double(max_size);
            other.resize_double(max_size);
        }else{
            auto max_size = size_other;
            auto min_size = size;
            reserve_double(max_size);
            resize_double(max_size);
        }
        SEAL_ITERATE(iter(double_data_.begin(), other.double_data()),coeff_count(), [&](auto I){
                get<0>(I) += get<1>(I);
                
            });
            
    }

    void add_the_multiply_inplace_double(Poly& other, double_t multiplicand){
        auto size = coeff_count();
        auto size_other = other.coeff_count();
        auto max_size = max(size, size_other);

        if(size > size_other){
            auto max_size = size;
            auto min_size = size_other;
            other.reserve_double(max_size);
            other.resize_double(max_size);
        }else{
            auto max_size = size_other;
            auto min_size = size;
            reserve_double(max_size);
            resize_double(max_size);
        }
        // other.to_double();
        auto other_double = other.double_data();

        SEAL_ITERATE(seal::util::iter(other_double, double_data(), size_t(0)), coeff_count(), [&](auto I){
            get<1>(I) += get<0>(I)*multiplicand;
        });
    }

    void to_double(){
        double_data_.resize(coeff_count());
        SEAL_ITERATE(seal::util::iter(double_data_.begin(), data()), coeff_count(), [&](auto I){
            get<0>(I) = static_cast<double_t>(get<1>(I));
        });
    }

    void to_int(){
        SEAL_ITERATE(seal::util::iter(double_data_.begin(),data()), coeff_count(), [&](auto I){
            
            get<1>(I) = static_cast<uint64_t>(get<0>(I));
        });
    }
    static Poly ones(SEALContext context){
        Poly new_poly(context, "0");
        SEAL_ITERATE(iter(new_poly.data(), new_poly.double_data()), new_poly.coeff_count(), [&](auto I){
            get<0>(I) = 1;
            get<1>(I) = 1.0f;
        });
        return new_poly;
    }
    static Poly get_random_poly(SEALContext context, shared_ptr<UniformRandomGenerator> poly_prng, string what_type="uniform"){
        Poly new_poly(context, "0");
        auto &context_data = *context.key_context_data();
        auto &parms = context_data.parms();
        if(what_type=="uniform"){
            sample_poly_uniform(poly_prng, parms, new_poly.data());
            new_poly.to_double();
        }
        else{
            Poly temp(context);
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_modulus_size = coeff_modulus.size();
            RNSIter new_poly_iter(temp.data(),coeff_count);
            sample_poly_ternary(poly_prng, parms, new_poly_iter);
            auto ntt_tables = context_data.small_ntt_tables();
            ntt_negacyclic_harvey(new_poly_iter, coeff_modulus_size, ntt_tables);
            temp.to_double();

            // new_poly = temp;
            // new_poly.add_the_multiply_inplace_double(temp, 0.000000125);
            // cout << temp.to_string() << " 112 ";
            new_poly.to_int();
            // cout << new_poly.to_string() << endl;
        }
        
        
        return new_poly;
    }

    size_t poly_coeff_count() const{
        return poly_coeff_count_;
    }



    void add_the_multiply_inplace(Poly& other, unsigned long multiplicand){
        Poly temp(context_);
        temp = other;
        SEAL_ITERATE(iter(temp.double_data(), size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) *= multiplicand;
        });
        add_inplace(temp);
        to_int();
    }

    void reserve_double(size_t size){
        
        double_data_.reserve(size);
        reserve(size);
        
    }
    void resize_double(size_t size){
        double_data_.resize(size);
        resize(size);
    }

    void reduce_to_mod(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        uint64_t mod = coeff_modulus[0].value();
        SEAL_ITERATE(iter(data(),size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) = get<0>(I)%mod;
        });
    }

    void negate(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        uint64_t mod = coeff_modulus[0].value();
        SEAL_ITERATE(iter(data(),size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) = (mod-get<0>(I))%mod;
        });
    }

    

    auto to_string_db(){
        Poly temp(context_);
        temp = *this;
        temp.to_int();
        // reduce_to_mod();
        return temp.to_string();
    }

    double_t *double_data(){
        return double_data_.begin();
    }

    PublicKey& to_publickey(Poly a){
        PublicKey* pk = new PublicKey();
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        auto ntt_tables = context_data.small_ntt_tables();
        size_t coeff_modulus_size = coeff_modulus.size();
        
        Ciphertext& destination = pk->data();
        destination.resize(context_, context_data.parms_id(), 2);
        destination.is_ntt_form() = true;
        destination.scale() = 1.0;
        destination.correction_factor() = 1;

        uint64_t *c0 = destination.data();
        uint64_t *c1 = destination.data(1);
        add_poly_coeffmod(c0,data(),coeff_count, coeff_modulus[0],c0);
        add_poly_coeffmod(c1,a.data(),coeff_count, coeff_modulus[0],c1);

        return *pk;
    }

    SecretKey& to_secretkey(bool is_initialized=false)
    {
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        if (!is_initialized)
        {
            // Initialize secret key.
            sk_ = SecretKey();
            sk_generated_ = false;
            sk_.data().resize(mul_safe(coeff_count, coeff_modulus_size));

            // Generate secret key
            SEAL_ITERATE(iter(sk_.data().data(),data()), coeff_count, [&](auto I) {
                get<0>(I) = get<1>(I);
            });
            sk_.parms_id() = context_data.parms_id();
        }

        // Set the secret_key_array to have size 1 (first power of secret)
        // secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
        set_poly(sk_.data().data(), coeff_count, coeff_modulus_size, data());

        // Secret key has been generated
        sk_generated_ = true;
        return sk_;
    }

    SecretKey& sk(){
       return sk_; 
    }

    void multiply_polynomial(uint64_t* other, Poly& result){
        // result.to_double();
        SEAL_ITERATE(iter(double_data(), other, result.double_data()), coeff_count(), [&](auto I){
            get<2>(I)=get<0>(I)*get<1>(I);
        });
    }

private:
    SEALContext context_;
    size_t poly_coeff_count_ = 0;
    vector<Modulus> coeff_mod_;
    size_t coeff_mod_size_;
    DynArray<double_t> double_data_;
    SecretKey sk_;
    bool sk_generated_;
};