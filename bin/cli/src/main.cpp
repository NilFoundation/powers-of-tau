#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <filesystem>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/zk/commitments/polynomial/powers_of_tau.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/powers_of_tau/public_key.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/proof_of_knowledge.hpp>

using namespace nil::crypto3;

using curve_type = algebra::curves::bls12<381>;
static constexpr const unsigned tau_powers = 32;
using scheme_type = zk::commitments::powers_of_tau<curve_type, tau_powers>;
using private_key_type = scheme_type::private_key_type;
using public_key_type = scheme_type::public_key_type;
using accumulator_type = scheme_type::accumulator_type;

struct marshalling_policy {
    using endianness = nil::marshalling::option::little_endian;
    using field_base_type = nil::marshalling::field_type<endianness>;
    using accumulator_marshalling_type = nil::crypto3::marshalling::types::powers_of_tau_accumulator<field_base_type, accumulator_type>;
    using public_key_marshalling_type = nil::crypto3::marshalling::types::powers_of_tau_public_key<field_base_type, public_key_type>;
    using pok_marshalling_type = nil::crypto3::marshalling::types::element_pok<field_base_type, zk::commitments::detail::element_pok<curve_type>>;

    template<typename MarshalingType, typename InputObj, typename F>
    static std::vector<std::uint8_t> serialize_obj(const InputObj &in_obj, const std::function<F> &f) {
        MarshalingType filled_val = f(in_obj);
        std::vector<std::uint8_t> blob(filled_val.length());
        auto it = std::begin(blob);
        nil::marshalling::status_type status = filled_val.write(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        return blob;
    }

    template<typename MarshalingType, typename ReturnType, typename InputBlob, typename F>
    static ReturnType deserialize_obj(const InputBlob &blob, const std::function<F> &f) {
        MarshalingType marshaling_obj;
        auto it = std::cbegin(blob);
        nil::marshalling::status_type status = marshaling_obj.read(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        return f(marshaling_obj);
    }

    static std::vector<std::uint8_t> serialize_accumulator(const accumulator_type& acc) {
        return serialize_obj<accumulator_marshalling_type>(acc,
            std::function(nil::crypto3::marshalling::types::fill_powers_of_tau_accumulator<accumulator_type, endianness>));
    }

    static accumulator_type deserialize_accumulator(const std::vector<std::uint8_t>& blob) {
        return deserialize_obj<accumulator_marshalling_type, accumulator_type>(blob,
            std::function(nil::crypto3::marshalling::types::make_powers_of_tau_accumulator<accumulator_type, endianness>));
    }

    static std::vector<std::uint8_t> serialize_public_key(const public_key_type& public_key) {
        return serialize_obj<public_key_marshalling_type>(public_key,
            std::function(nil::crypto3::marshalling::types::fill_powers_of_tau_public_key<public_key_type, endianness>));
    }

    static std::pair<accumulator_type, public_key_type> deserialize_response(std::vector<std::uint8_t> blob) {
        accumulator_marshalling_type acc_marsh;
        auto it = std::cbegin(blob);
        nil::marshalling::status_type status = acc_marsh.read(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        accumulator_type acc  = nil::crypto3::marshalling::types::make_powers_of_tau_accumulator<accumulator_type, endianness>(acc_marsh);

        public_key_marshalling_type pk_marsh;
        status = pk_marsh.read(it, blob.size() - acc_marsh.length());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        public_key_type pk  = nil::crypto3::marshalling::types::make_powers_of_tau_public_key<public_key_type, endianness>(pk_marsh);

        return {acc, pk};
    }

    template<typename Path, typename Blob>
    static void write_obj(const Path &path, std::initializer_list<Blob> blobs) {
        if (std::filesystem::exists(path)) {
            std::cout << "File " << path << " exists and won't be overwritten." << std::endl;
            return;
        }
        std::ofstream out(path, std::ios_base::binary);
        for (const auto &blob : blobs) {
            for (const auto b : blob) {
                out << b;
            }
        }
        out.close();
    }

    template<typename Path>
    static std::vector<std::uint8_t> read_obj(const Path &path) {
        BOOST_ASSERT_MSG(
                std::filesystem::exists(path),
                (std::string("File ") + path + std::string(" doesn't exist, make sure you created it!")).c_str());
        std::ifstream in(path, std::ios_base::binary);
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto blob_str = buffer.str();
        return {std::cbegin(blob_str), std::cend(blob_str)};
    }

};

accumulator_type init_ceremony() {
    accumulator_type acc;
    return acc;
}

public_key_type contribute_randomness(accumulator_type &acc) {
    private_key_type private_key = scheme_type::generate_private_key();
    public_key_type public_key = scheme_type::proof_eval(private_key, acc);
    
    acc.transform(private_key);
    return public_key;
}

bool verify_contribution(const accumulator_type &before,
                         const accumulator_type &after,
                         const public_key_type &public_key) {
    return scheme_type::verify_eval(public_key, before, after);
}

int main(int argc, char *argv[]) {
    std::string description =
        "Powers of Tau, A Trusted Setup Multi Party Computation Protcol\n"
        "Usage:\n"
        "init - Initialize the a trusted setup MPC ceremony\n"
        "contribute - Contribute randomness to the trusted setup\n"
        "verify - Verify a contribution to the trusted setup\n"
        "\n"
        "Run `cli subcommand --help` for details about a specific subcommand";
    
    if(argc < 2) {
        std::cout << description << std::endl;
        return 0;
    }

    std::string command = argv[1];
    if(command == "init") {
        std::string output_path = "challenge";
        std::cout << "Initializing Powers Of Tau challenge" << std::endl;
        auto acc = init_ceremony();
        std::vector<std::uint8_t> acc_blob = marshalling_policy::serialize_accumulator(acc);
        marshalling_policy::write_obj(output_path, {acc_blob});
        std::cout << "Challenge written to " << output_path << std::endl;
    } else if(command == "contribute") {
        std::string challenge_path = "challenge";
        std::string response_path = "response";
        std::vector<std::uint8_t> challenge_blob = marshalling_policy::read_obj(challenge_path);
        accumulator_type acc = marshalling_policy::deserialize_accumulator(challenge_blob);
        public_key_type public_key = contribute_randomness(acc);
        std::vector<std::uint8_t> response_blob =  marshalling_policy::serialize_accumulator(acc);
        std::vector<std::uint8_t> public_key_blob = marshalling_policy::serialize_public_key(public_key);
        marshalling_policy::write_obj(response_path, {response_blob, public_key_blob});
    } else if(command=="verify") {
        std::string before_path = "before";
        std::string after_path = "after";
        std::vector<std::uint8_t> before_blob = marshalling_policy::read_obj(before_path);
        std::vector<std::uint8_t> after_blob = marshalling_policy::read_obj(after_path);
        accumulator_type before = marshalling_policy::deserialize_accumulator(before_blob);
        auto [after, pk] = marshalling_policy::deserialize_response(after_blob);
        bool is_valid = verify_contribution(before, after, pk);
        std::cout << (is_valid ? "Contribution is valid!" : "Contribution is invalid!");
    } else {
        std::cout << "invalid command: " << command << std::endl;
        std::cout << description << std::endl;
    }
    return 0;
}