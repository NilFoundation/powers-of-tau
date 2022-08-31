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

namespace po = boost::program_options;

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
        "init - Initialize a trusted setup MPC ceremony\n"
        "contribute - Contribute randomness to the trusted setup\n"
        "verify - Verify a contribution to the trusted setup\n"
        "\n"
        "Run `cli subcommand --help` for details about a specific subcommand";
    
    int usage_error_exit_code = 1;
    int help_message_exit_code = 2;
    int invalid_exit_code = 3;
    
    if(argc < 2) {
        std::cout << description << std::endl;
        return help_message_exit_code;
    }

    std::string command = argv[1];
    if(command == "init") {
        po::options_description desc("init - Initialize a trusted setup MPC ceremony");
        desc.add_options()("help,h", "Display help message")
        ("output,o", po::value<std::string>(), "Initial challenge output path");

        po::variables_map vm;
        po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
        po::notify(vm);

        if(argc < 3 || vm.count("help")) {
            std::cout << desc << std::endl;
            return help_message_exit_code;
        }

        if(!vm.count("output")) {
            std::cout << "missing argument -o [ --output ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }
        
        std::string output_path = vm["output"].as<std::string>();
        std::cout << "Initializing Powers Of Tau challenge..." << std::endl;
        auto acc = init_ceremony();

        std::cout << "Writing to file..." << std::endl;

        std::vector<std::uint8_t> acc_blob = marshalling_policy::serialize_accumulator(acc);
        marshalling_policy::write_obj(output_path, {acc_blob});
        std::cout << "Challenge written to " << output_path << std::endl;
    } else if(command == "contribute") {
        po::options_description desc("contribute - Contribute randomness to the trusted setup");
        desc.add_options()("help,h", "Display help message")
        ("challenge,c", po::value<std::string>(), "challenge input path")
        ("output,o", po::value<std::string>(), "Response output path");

        po::variables_map vm;
        po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
        po::notify(vm);

        if(argc < 3 || vm.count("help")) {
            std::cout << desc << std::endl;
            return help_message_exit_code;
        }

        if(!vm.count("challenge")) {
            std::cout << "missing argument -c [ --challenge ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        if(!vm.count("output")) {
            std::cout << "missing argument -o [ --output ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }
        
        std::string challenge_path = vm["challenge"].as<std::string>();
        std::string output_path = vm["output"].as<std::string>();
        
        std::cout << "Reading challenge file: " << challenge_path << std::endl;
        
        std::vector<std::uint8_t> challenge_blob = marshalling_policy::read_obj(challenge_path);
        accumulator_type acc = marshalling_policy::deserialize_accumulator(challenge_blob);

        std::cout << "Contributing randomness..." << std::endl;

        public_key_type public_key = contribute_randomness(acc);
        
        std::cout << "Writing to file..." << std::endl;
        
        std::vector<std::uint8_t> response_acc_blob =  marshalling_policy::serialize_accumulator(acc);
        std::vector<std::uint8_t> public_key_blob = marshalling_policy::serialize_public_key(public_key);
        marshalling_policy::write_obj(output_path, {response_acc_blob, public_key_blob});

        std::cout << "Reponse written to " << output_path << std::endl;
    } else if(command=="verify") {
        po::options_description desc("verify - Contribute randomness to the trusted setup");
        desc.add_options()("help,h", "Display help message")
        ("challenge,c", po::value<std::string>(), "Path to challenge file")
        ("response,r", po::value<std::string>(), "Path to response file");

        po::variables_map vm;
        po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
        po::notify(vm);

        if(argc < 3 || vm.count("help")) {
            std::cout << desc << std::endl;
            return help_message_exit_code;
        }

        if(!vm.count("challenge")) {
            std::cout << "missing argument -c [ --challenge ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        if(!vm.count("response")) {
            std::cout << "missing argument -r [ --response ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        std::string challenge_path = vm["challenge"].as<std::string>();
        std::string response_path = vm["response"].as<std::string>();

        std::cout << "Reading files challenge: " << challenge_path << " response: " << response_path << std::endl;

        std::vector<std::uint8_t> challenge_blob = marshalling_policy::read_obj(challenge_path);
        std::vector<std::uint8_t> reponse_blob = marshalling_policy::read_obj(response_path);
        accumulator_type before = marshalling_policy::deserialize_accumulator(challenge_blob);
        auto [after, pk] = marshalling_policy::deserialize_response(reponse_blob);
        
        std::cout << "Verifying contribution..." << std::endl;
        
        bool is_valid = verify_contribution(before, after, pk);
        std::cout << (is_valid ? "Contribution is valid!" : "Contribution is invalid!") << std::endl;
        if(!is_valid) {
            return 1;
        }
    } else {
        std::cout << "invalid command: " << command << std::endl;
        std::cout << description << std::endl;
        return usage_error_exit_code;
    }

    return 0;
}