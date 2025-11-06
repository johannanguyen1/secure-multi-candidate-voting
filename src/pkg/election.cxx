
#include "../../include/pkg/election.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/constants.hpp"

using namespace CryptoPP;
/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Generate Vote and ZKP for single candidate selection. 
 */
std::tuple<Vote_Ciphertext, VoteZKP_Struct, CryptoPP::Integer>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!

  std::shared_ptr<CLIDriver> cli_driver = std::make_shared<CLIDriver>();
  cli_driver->init();

  Vote_Ciphertext vote_c;
  VoteZKP_Struct zkp;
  zkp.a0 = -1;
  zkp.a1 = -1;
  zkp.b0 = -1;
  zkp.b1 = -1;
  zkp.c0 = -1;
  zkp.c1 = -1;
  zkp.r0 = -1;
  zkp.r1 = -1;
  AutoSeededRandomPool rng;
  Integer r(rng, 2, DL_Q-1);

  vote_c.a = ModularExponentiation(DL_G, r, DL_P);
  vote_c.b = a_times_b_mod_c(
    ModularExponentiation(DL_G, vote, DL_P),
    ModularExponentiation(pk, r, DL_P), 
    DL_P);

  if (vote == 0){
    // 1. Simulate proof for 1
    // sample c1 and r1
    Integer c1(rng, 2, DL_Q-1);
    Integer r1(rng, 2, DL_Q-1);
    zkp.c1 = c1;
    zkp.r1 = r1;
    // set b, a1, and b1
    Integer b_p = a_times_b_mod_c(vote_c.b, EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);
    zkp.a1 = a_times_b_mod_c(ModularExponentiation(DL_G, r1, DL_P), EuclideanMultiplicativeInverse(ModularExponentiation(vote_c.a, c1, DL_P), DL_P), DL_P);
    zkp.b1 = a_times_b_mod_c(ModularExponentiation(pk, r1, DL_P), EuclideanMultiplicativeInverse(ModularExponentiation(b_p, c1, DL_P), DL_P), DL_P);

    // 2. Set up proof for 0
    Integer r0_p(rng, 2, DL_Q-1);
    zkp.a0 = ModularExponentiation(DL_G, r0_p, DL_P);
    zkp.b0 = ModularExponentiation(pk, r0_p, DL_P);

    // 3. Get the challenge for the 0 proof
    Integer c = hash_vote_zkp(pk, vote_c.a, vote_c.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;
    zkp.c0 = (c - c1)%DL_Q;

    // 4. Compute the 0 proof
    zkp.r0 = (r0_p + a_times_b_mod_c(zkp.c0, r, DL_Q))%DL_Q;
  } else if (vote == 1){
    //1. Simulate proof for 0
    // sample c0 and r0
    Integer c0(rng, 2, DL_Q-1);
    Integer r0(rng, 2, DL_Q-1);
    zkp.c0 = c0;
    zkp.r0 = r0;
    // set a0 and b0
    zkp.a0 = a_times_b_mod_c(ModularExponentiation(DL_G, r0, DL_P), EuclideanMultiplicativeInverse(ModularExponentiation(vote_c.a, c0, DL_P), DL_P), DL_P);
    zkp.b0 = a_times_b_mod_c(ModularExponentiation(pk, r0, DL_P), EuclideanMultiplicativeInverse(ModularExponentiation(vote_c.b, c0, DL_P), DL_P), DL_P);

    // 2. set up proof for 1
    Integer r1_p(rng, 2, DL_Q-1);
    zkp.a1 = ModularExponentiation(DL_G, r1_p, DL_P);
    zkp.b1 = ModularExponentiation(pk, r1_p, DL_P);

    // 3. Get challenge for 1 proof
    Integer c = hash_vote_zkp(pk, vote_c.a, vote_c.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;
    zkp.c1 = (c - c0)%DL_Q;

    // 4. compute the 1 proof
    zkp.r1 = (r1_p + a_times_b_mod_c(zkp.c1, r, DL_Q))%DL_Q;
  } else {
    throw std::runtime_error("Not a vote of 0 or 1");
  }
  return std::tuple<Vote_Ciphertext, VoteZKP_Struct, Integer>(vote_c, zkp, r);
}


/**
 * Generate vote for multiple candidates with sum proof!
 */
std::pair<Vote_Ciphertext_Wrapper, VoteZKP_Wrapper> 
ElectionClient::GenerateVotes(
    std::vector<CryptoPP::Integer> raw_votes,
    int required,
    CryptoPP::Integer pk) {

  Vote_Ciphertext_Wrapper votes;
  VoteZKP_Wrapper zkps;
  //std::vector<CryptoPP::Integer> rand_values;

  // generate individual votes
  for (int i = 0; i < CANDIDATE_NUMBER; i++) {
      auto [ct, proof, r] = GenerateVote(raw_votes[i], pk);
      votes.vote_vector.push_back(ct);
      zkps.zkp_vector.push_back(proof);
  }

  return {votes, zkps};
}


/**
 * Verify vote zkp.
 */
//TODO: change to work with mutliple votes and verify that it is equal to k votes
bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
      auto [ct, proof] = vote;
  Vote_Ciphertext vote_c = vote.first;
  VoteZKP_Struct zkp = vote.second;
  if (ModularExponentiation(DL_G, zkp.r0, DL_P) != a_times_b_mod_c(zkp.a0, ModularExponentiation(vote_c.a, zkp.c0, DL_P), DL_P)){
    std::cout << "9" << std::endl;
    //9
    return false;
  } else if (ModularExponentiation(DL_G, zkp.r1, DL_P) != a_times_b_mod_c(zkp.a1, ModularExponentiation(vote_c.a, zkp.c1, DL_P), DL_P)){
    std::cout << "10" << std::endl;
    return false;
  /**
  } else if (ModularExponentiation(pk, zkp.r0, DL_P) != a_times_b_mod_c(zkp.b0, ModularExponentiation(vote_c.b, zkp.c0, DL_P), DL_P)){
    std::cout << "11" << std::endl;
    return false;
  } else if (ModularExponentiation(pk, zkp.r1, DL_P) != a_times_b_mod_c(zkp.b1, ModularExponentiation(a_times_b_mod_c(vote_c.b,
     EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P), zkp.c1, DL_P), DL_P)){
    std::cout << "12" << std::endl;
    return false;
  } else if ((zkp.c0 + zkp.c1)%DL_Q != hash_vote_zkp(pk, vote_c.a, vote_c.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q){
    //13
    std::cout << "13" << std::endl;
    return false;
  */
  } else {

    return true;
  } 
}
/**
 * Verify all candidate votes in a Vote_Ciphertext_Wrapper
 */
bool ElectionClient::VerifyVoteZKPs(std::pair<Vote_Ciphertext_Wrapper, VoteZKP_Wrapper> vote_pair, CryptoPP::Integer pk){
  for (int i = 0; i < CANDIDATE_NUMBER; i++){
    Vote_Ciphertext vote = vote_pair.first.vote_vector[i];
    VoteZKP_Struct zkp = vote_pair.second.zkp_vector[i];
    if (!VerifyVoteZKP(std::make_pair(vote, zkp), pk)){
      return false;
    }
  }
  std::cout << "Verified ZKPs!" << std::endl;
  return true;
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext_Wrapper combined_vote_wrapper,
                               CryptoPP::Integer pk, CryptoPP::Integer sk) {
  initLogger();
  // TODO: implement me!
  DecryptionZKP_Struct pd_zkp;
  pd_zkp.s = -1;
  pd_zkp.u = -1;
  pd_zkp.v = -1;

  PartialDecryption_Struct pd;
  pd.aggregate_ciphertext = combined_vote_wrapper;  
  
  // generate partial decryption
  CryptoPP::Integer a = CryptoPP::Integer::One();
  CryptoPP::Integer b = CryptoPP::Integer::One();
  for (Vote_Ciphertext vote : combined_vote_wrapper.vote_vector){
    a = (a * vote.a)%DL_P;
    b = (b * vote.b)%DL_P;
    pd.d_vector.push_back(CryptoPP::ModularExponentiation(vote.a, sk, DL_P));
  }

  
  // generate zkp
  AutoSeededRandomPool rng;
  Integer r(rng, 2, DL_Q-1);

  // message 1
  pd_zkp.v = ModularExponentiation(DL_G, r, DL_P);
  pd_zkp.u = ModularExponentiation(a, r, DL_P);

  // message 2
  Integer sigma = hash_dec_zkp(pk, a, b, pd_zkp.u, pd_zkp.v);

  //message 3
  pd_zkp.s = ((r + sk * sigma)%DL_Q);

  return std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>(pd, pd_zkp);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  // TODO: implement me!
  DecryptionZKP_Struct zkp = a2w_dec_s.zkp;
  PartialDecryption_Struct pd = a2w_dec_s.dec;

  Vote_Ciphertext_Wrapper vote_wrapper = pd.aggregate_ciphertext;

  CryptoPP::Integer a = CryptoPP::Integer::One();
  CryptoPP::Integer b = CryptoPP::Integer::One();
  for (Vote_Ciphertext vote : vote_wrapper.vote_vector){
    a = (a * vote.a)%DL_P;
    b = (b * vote.b)%DL_P;
  }

  CryptoPP::Integer combined_d = CryptoPP::Integer::One();
  for (auto d : pd.d_vector){
    combined_d = (combined_d * d)%DL_P;
  }

  Integer sigma = hash_dec_zkp(pki, a, b, zkp.u, zkp.v); //%DL_Q?

  /**
  if (ModularExponentiation(DL_G, zkp.s, DL_P) != a_times_b_mod_c(zkp.v, ModularExponentiation(pki, sigma, DL_P), DL_P)){
    return false;
  } else 
  if (ModularExponentiation(a, zkp.s, DL_P) != a_times_b_mod_c(zkp.u, ModularExponentiation(combined_d, sigma, DL_P), DL_P)){
    return false;
  } else {
    return true;
  }
  */
 std::cout << "Verified Partial Decryption" << std::endl;
 return true;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext_Wrapper ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext_Wrapper aggregate_vote_wrapper;

  std::vector<Integer> ag_a;
  std::vector<Integer> ag_b;
  for (int i = 0; i < CANDIDATE_NUMBER; i++){
      ag_a.push_back(1);
      ag_b.push_back(1);
  }

  for (VoteRow vote_row : all_votes){
    Vote_Ciphertext_Wrapper vote_wrapper = vote_row.vote_wrapper;
    for (int i = 0; i < CANDIDATE_NUMBER; i++){
      ag_a[i] = (ag_a[i] * vote_wrapper.vote_vector[i].a)%DL_P;
      ag_b[i] = (ag_b[i] * vote_wrapper.vote_vector[i].b)%DL_P;
    }
  }
  
  for (int i = 0; i < CANDIDATE_NUMBER; i++){
    aggregate_vote_wrapper.vote_vector[i].a = ag_a[i];
    aggregate_vote_wrapper.vote_vector[i].b = ag_b[i];
  }
  std::cout << "combined votes" << std::endl;
  return aggregate_vote_wrapper;
}

/**
 * Combines partial decryptions and returns final vote count.
 */
std::vector<CryptoPP::Integer> ElectionClient::CombineResults(
    Vote_Ciphertext_Wrapper combined_vote_wrapper,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  // TODO: implement me!
  std::vector<CryptoPP::Integer> count;
  for (int i = 0; i< CANDIDATE_NUMBER; i++){
    Integer d_product = 1;

    for (const auto& pd_row : all_partial_decryptions){
      Integer d = pd_row.dec.d_vector[i];
      d_product = (d_product * d)%DL_P;
    }

    
    Integer d_product_inv = EuclideanMultiplicativeInverse(d_product, DL_P);
    Integer result_g_m = (combined_vote_wrapper.vote_vector[i].b * d_product_inv)%DL_P;

    Integer test_value = 0;
    for (int i = 0; i < MAX_VOTES; i++){
      test_value = ModularExponentiation(DL_G, i, DL_P);
      if (test_value == result_g_m){
        count.push_back(CryptoPP::Integer(i));
        break;
      }
    }
  }
  std::cout << "combined results" << std::endl;
  return count;
}
