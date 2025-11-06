#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/network_driver.hpp"
#include "../include/pkg/election.hpp"
#include "doctest/doctest.h"
#include "../include-shared/constants.hpp"
#include "../include-shared/keyloaders.hpp"


TEST_CASE("sample") {
    std::cout << "TESTING: sample" << std::endl;
    CHECK(0 == 0);
}

TEST_CASE("Vote_Ciphertext_Wrapper"){
    std::cout << "TESTING: vote ciphertext wrapper" << std::endl;
    
    Vote_Ciphertext vote;
    vote.a = CryptoPP::Integer::Zero();
    vote.b = CryptoPP::Integer::One();

    Vote_Ciphertext_Wrapper vote_wrapper1;
    vote_wrapper1.vote_vector.push_back(vote);
    std::cout << "made vote wrapper" << std::endl;

    std::vector<unsigned char> data;
    vote_wrapper1.serialize(data);
    std::cout << "deserialized vote wrapper" << std::endl;

    Vote_Ciphertext_Wrapper vote_wrapper2;
    vote_wrapper2.deserialize(data);
    std::cout << "serialized vote wrapper" << std::endl;

    CHECK(vote_wrapper2.vote_vector[0].a == CryptoPP::Integer::Zero());
    CHECK(vote_wrapper2.vote_vector[0].b == CryptoPP::Integer::One());
}

TEST_CASE("Vote Argument"){
    std::cout << "TESTING: vote argument" << std::endl;
    std::vector<std::string> args = {"register", "localhost", "5000", "1", "0", "1", "0"};
    std::vector<CryptoPP::Integer> raw_vote;
    for (int i = 3; i < 3 + CANDIDATE_NUMBER; i++){
        if (args[i] == "0"){
            raw_vote.push_back(CryptoPP::Integer::Zero());
        } else if (args[i] == "1"){
            raw_vote.push_back(CryptoPP::Integer::One());
        }
    }
    CHECK(raw_vote[0] == CryptoPP::Integer::One());
    CHECK(raw_vote[1] == CryptoPP::Integer::Zero());
    CHECK(raw_vote[2] == CryptoPP::Integer::One());
    CHECK(raw_vote[3] == CryptoPP::Integer::Zero());
}

TEST_CASE("Generate Votes"){
    std::cout << "TESTING: vote generation" << std::endl;

    std::vector<std::string> args = {"register", "localhost", "5000", "1", "0", "1", "0"};
    std::vector<CryptoPP::Integer> raw_vote;
    for (int i = 3; i < 3 + CANDIDATE_NUMBER; i++){
        if (args[i] == "0"){
            raw_vote.push_back(CryptoPP::Integer::Zero());
        } else if (args[i] == "1"){
            raw_vote.push_back(CryptoPP::Integer::One());
        }
    }

    CryptoDriver crypto_driver;
    std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
        crypto_driver.EG_generate();
    ElectionClient election;
    auto result = election.GenerateVotes(raw_vote, REQUIRED_VOTE_NUMBER, keys.second);

    CHECK(result.first.vote_vector.size() == 4);
    CHECK(result.second.zkp_vector.size() == 4);
}


TEST_CASE("Verify Votes"){
    std::cout << "TESTING: vote generation" << std::endl;

    std::vector<std::string> args = {"register", "localhost", "5000", "1", "0", "1", "0"};
    std::vector<CryptoPP::Integer> raw_vote;
    for (int i = 3; i < 3 + CANDIDATE_NUMBER; i++){
        if (args[i] == "0"){
            raw_vote.push_back(CryptoPP::Integer::Zero());
        } else if (args[i] == "1"){
            raw_vote.push_back(CryptoPP::Integer::One());
        }
    }

    CryptoDriver crypto_driver;
    std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
        crypto_driver.EG_generate();
    ElectionClient election;
    auto result = election.GenerateVotes(raw_vote, REQUIRED_VOTE_NUMBER, keys.second);

    CHECK(election.VerifyVoteZKPs(result, keys.second));
}


