#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/modarith.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/db_driver.hpp"

class ElectionClient {
public:
  static std::tuple<Vote_Ciphertext, VoteZKP_Struct, CryptoPP::Integer>
  GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk);
  static std::pair<Vote_Ciphertext_Wrapper, VoteZKP_Wrapper>
  GenerateVotes(std::vector<CryptoPP::Integer> raw_votes, int required, CryptoPP::Integer pk);
  static void generateSumProof(const Vote_Ciphertext_Wrapper votes, int required, VoteZKP_Wrapper& proofs, const std::vector<CryptoPP::Integer>& rand_vals, const CryptoPP::Integer& pk);
  static bool VerifyVoteZKP(std::pair<Vote_Ciphertext, VoteZKP_Struct> vote,
                            CryptoPP::Integer pk);
  static bool VerifyVoteZKPs(std::pair<Vote_Ciphertext_Wrapper, VoteZKP_Wrapper> vote, CryptoPP::Integer pk);

  static std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
  PartialDecrypt(Vote_Ciphertext_Wrapper combined_vote_wrapper, CryptoPP::Integer pk,
                 CryptoPP::Integer sk);
  static bool
  VerifyPartialDecryptZKP(ArbiterToWorld_PartialDecryption_Message a2w_dec_s,
                          CryptoPP::Integer pki);

  static Vote_Ciphertext_Wrapper CombineVotes(std::vector<VoteRow> all_votes);
  static std::vector<CryptoPP::Integer>
  CombineResults(Vote_Ciphertext_Wrapper combined_vote_wrapper,
                 std::vector<PartialDecryptionRow> all_partial_decryptions);
};
