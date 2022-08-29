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

    template<typename MarshalingType, typename InputObj, typename F>
    static std::vector<std::uint8_t> serialize_obj(const InputObj &in_obj, const std::function<F> &f) {
        MarshalingType filled_val = f(in_obj);
        std::vector<std::uint8_t> blob(filled_val.length());
        auto it = std::begin(blob);
        nil::marshalling::status_type status = filled_val.write(it, blob.size());
        return blob;
    }

    template<typename MarshalingType, typename ReturnType, typename InputBlob, typename F>
    static ReturnType deserialize_obj(const InputBlob &blob, const std::function<F> &f) {
        MarshalingType marshaling_obj;
        auto it = std::cbegin(blob);
        nil::marshalling::status_type status = marshaling_obj.read(it, blob.size());
        return f(marshaling_obj);
    }

    static std::vector<std::uint8_t> serialize_accumulator(const accumulator_type& acc) {
        return serialize_obj<accumulator_marshalling_type>(acc,
            std::function(nil::crypto3::marshalling::types::fill_powers_of_tau_accumulator<accumulator_type, endianness>));
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
    boost::program_options::options_description desc(
        "Powers Of Tau, Trusted Setup Multi Party Computation Protocol "
        "(https://eprint.iacr.org/2017/1050) CLI Tool");

    desc.add_options()("help,h", "Display help message")
        ("phase,p", boost::program_options::value<std::string>(), "Execure protocol phase (init|contribute|verify)")
        ("output,o", boost::program_options::value<std::string>(), "Output path");
    
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
        .options(desc).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << desc << std::endl;
        return 0;
    }

    if(vm.count("phase")) {
        if(vm["phase"].as<std::string>() == "init") {
            if(!vm.count("output")) {
                std::cout << "missing argument -o [--output]";
                std::cout << desc;
                return 0;
            }
            std::string output_path = vm["output"].as<std::string>();
            auto acc = init_ceremony();
            std::vector<std::uint8_t> acc_blob = marshalling_policy::serialize_accumulator(acc);

        } else {
            std::cout << desc;
            return 0;
        }
    } else {
        std::cout << desc;
        return 0;
    }

    return 0;
}