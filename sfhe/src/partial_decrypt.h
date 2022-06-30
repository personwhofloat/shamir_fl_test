#pragma once
#include "seal/decryptor.h"
#include "seal/plaintext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include <vector>
#include <iostream>

class PartialDecryptor : public Decryptor{
public:
    PartialDecryptor(SEALContext& context, const SecretKey &secret_key):Decryptor(context, secret_key){}

    void dot_product_ct_sk_array(const Ciphertext &encrypted, Poly& destination, MemoryPoolHandle pool)
    {
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t key_coeff_modulus_size = context_.key_context_data()->parms().coeff_modulus().size();
        size_t encrypted_size = encrypted.size();
        auto is_ntt_form = encrypted.is_ntt_form();

        auto ntt_tables = context_data.small_ntt_tables();

        // Make sure we have enough secret key powers computed
        compute_secret_key_array(encrypted_size - 1);
        
        if (encrypted_size == 2)
        {
            auto c0 = encrypted.data(0);
            auto c1 = encrypted.data(1);
            // cout << is_ntt_form << endl;
            if (is_ntt_form)
            {
                set_uint(c1, coeff_count, destination.data());
                // destination.multiply_polynomial(&secret_key_array_[0], destination);
                dyadic_product_coeffmod(c1, secret_key_array_,coeff_count,0x3e0000000001,destination.data());
                add_poly_coeffmod(destination.data(), c0, coeff_count, coeff_modulus[0],destination.data());
                destination.to_double();
            }
            else
            {
                set_uint(c1, coeff_count, destination.data());
                ntt_negacyclic_harvey_lazy(destination.data(), ntt_tables[0]);
                dyadic_product_coeffmod(destination.data(), secret_key_array_,coeff_count,0x3e0000000001,destination.data());
                inverse_ntt_negacyclic_harvey(destination.data(), ntt_tables[0]);
                add_poly_coeffmod(destination.data(), c0, coeff_count, coeff_modulus[0],destination.data());
                destination.to_double();
            }
        }
    }
    void bfv_decrypt(const Ciphertext &encrypted, Poly &tmp_dest_modq)
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // Add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
        // Therefore, we can (integer) divide by Delta and the answer will round down to m.

        // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
        // SEAL_ALLOCATE_ZERO_GET_RNS_ITER(tmp_dest_modq_local, coeff_count, coeff_modulus_size, pool);
        // Poly tmp_dest_modq_local(context_);
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dot_product_ct_sk_array(encrypted, tmp_dest_modq, pool_);
        // SEAL_ITERATE(iter(tmp_dest_modq, tmp_dest_modq_local), 1, [&](auto I){
        //     add_poly_coeffmod(get<0>(I), get<1>(I), coeff_count, coeff_modulus[0], get<0>(I));
        // });
        
    }
    void post_process(Poly &destination){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        SEAL_ITERATE(iter(destination.double_data(), size_t(0)), coeff_count, [&](auto I){
            if(get<0>(I)<0) get<0>(I)=0;
        });
        destination.to_int();
        RNSIter tmp_dest_modq(destination.data(),coeff_count);
        // cout << "be\t" << destination.to_string()<<endl;
        // Divide scaling variant using BEHZ FullRNS techniques
        context_data.rns_tool()->decrypt_scale_and_round(tmp_dest_modq, destination.data(), pool_);
        
        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = get_significant_uint64_count_uint(destination.data(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
    }
};