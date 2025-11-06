#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    //Vote_Ciphertext_Wrapper vote;
    //LoadVoteWrapper(this->voter_config.voter_vote_path, vote);
    //this->vote = vote;

    //VoteZKP_Wrapper zkp;
    //LoadVoteZKPWrapper(this->voter_config.voter_vote_zkp_path, zkp);
    //this->vote_zkp = zkp;

    CryptoPP::Integer registrar_signature;
    LoadInteger(this->voter_config.voter_registrar_signature_path,
                registrar_signature);
    this->registrar_signature = registrar_signature;

    CryptoPP::Integer blind;
    LoadInteger(this->voter_config.voter_blind_path, blind);
    this->blind = blind;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0, 1}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 2) Blind the vote and send it to the registrar.
 * 3) Receive the blind signature from the registrar and save it.
 * 3) Receives and saves the signature from the server.
 */
//TODO: edit to take in multiple inputs? string might work
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3 + CANDIDATE_NUMBER) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote1>...<voten>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;

  //process vote argument
  std::vector<CryptoPP::Integer> raw_vote;
  for (int i = 3; i < 3 + CANDIDATE_NUMBER; i++){
    if (args[i] == "0"){
      raw_vote.push_back(CryptoPP::Integer::Zero());
    } else if (args[i] == "1"){
      raw_vote.push_back(CryptoPP::Integer::One());
    } else {
      this->cli_driver->print_warning("Vote must be 0 or 1.");
    }
  }

  // TODO: implement me!
  // handle key exchange
  auto keys = this->HandleKeyExchange(this->RSA_registrar_verification_key);
  SecByteBlock AES_key = keys.first;
  SecByteBlock HMAC_key = keys.second;

  // El Gamal encrypt the vote and generate a ZKP for it
  auto vote_pair = ElectionClient::GenerateVotes(raw_vote, REQUIRED_VOTE_NUMBER, this->EG_arbiter_public_key);
  Vote_Ciphertext_Wrapper vote_wrapper = vote_pair.first;
  VoteZKP_Wrapper zkp_wrapper = vote_pair.second;

  // blind the vote and send it
  VoterToRegistrar_Register_Message vote_message;
  vote_message.id = voter_id;
  
  auto blind_pair = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_wrapper);
  vote_message.vote = blind_pair.first;
  blind = blind_pair.second;
  std::vector<unsigned char> vote_data = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_message);
  network_driver->send(vote_data);

  // recieve blind signature and save it
  std::vector<unsigned char> raw_signature_data;
  raw_signature_data = network_driver->read();
  auto signature_data = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, raw_signature_data).first;
  RegistrarToVoter_Blind_Signature_Message signature_message;
  signature_message.deserialize(signature_data);

  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
  // to both memory and disk
  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  this->vote = vote_wrapper;
  this->vote_zkp = zkp_wrapper;
  this->registrar_signature = signature_message.registrar_signature;
  this->blind = blind;
  //SaveVoteWrapper(this->voter_config.voter_vote_path, vote_wrapper);
  //SaveVoteZKPWrapper(this->voter_config.voter_vote_zkp_path, zkp_wrapper);
  SaveInteger(this->voter_config.voter_registrar_signature_path,
              signature_message.registrar_signature);
  SaveInteger(this->voter_config.voter_blind_path, blind);

  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in
 * `this->registrar_signature`.
 * 3) Sends the vote, ZKP, and unblinded signature
 * to the tallyer.
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!
  // handle key exchange
  auto keys = this->HandleKeyExchange(this->RSA_tallyer_verification_key);
  AES_key = keys.first;
  HMAC_key = keys.second;
  
  // unblinds the registrar signature
  Integer unblinded_signature = this->crypto_driver->RSA_BLIND_unblind(this->RSA_registrar_verification_key, this->registrar_signature, this->blind); 

  // sends the vote, ZKP, and unblinded signature
  VoterToTallyer_Vote_Message vote_message;
  vote_message.vote_wrapper = this->vote;
  vote_message.zkp_wrapper = this->vote_zkp;
  vote_message.unblinded_signature = unblinded_signature;
  std::vector<unsigned char> vote_data = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_message);
  network_driver->send(vote_data); 
  // --------------------------------
  // Exit cleanly.
  this->network_driver->disconnect();
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!result.second) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  /** 
  this->cli_driver->print_success("Number of votes for 0: " +
                                  CryptoPP::IntToString(std::get<0>(result)));
  this->cli_driver->print_success("Number of votes for 1: " +
                                  CryptoPP::IntToString(std::get<1>(result)));
  */
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::pair<std::vector<CryptoPP::Integer>, bool> VoterClient::DoVerify() {
  // TODO: implement me!
  // 1. verifies all vote zkps and their signatures
  std::cout << "Election successful" << std::endl;
  std::vector<VoteRow> votes = this->db_driver->all_votes();
  std::vector<VoteRow> valid_votes;
  for (int i = 0; i < votes.size(); i++){
    VoteRow vote = votes[i];
    std::vector<unsigned char> vote_data;
    vote.serialize(vote_data);
    if (!ElectionClient::VerifyVoteZKPs(std::pair<Vote_Ciphertext_Wrapper, VoteZKP_Wrapper>(vote.vote_wrapper, vote.zkp_wrapper), this->EG_arbiter_public_key)){continue;}
    if (!this->crypto_driver->RSA_BLIND_verify(this->RSA_registrar_verification_key, vote.vote_wrapper, vote.unblinded_signature)){continue;}
    //if (!this->crypto_driver->RSA_verify(this->RSA_tallyer_verification_key, concat_vote_zkp_and_signature(vote.vote_wrapper, vote.zkp_wrapper, vote.unblinded_signature), vote.tallyer_signature)){continue;}
    valid_votes.push_back(vote);
  }
  auto one_vote = ElectionClient::CombineVotes(valid_votes);

  // 2. verifies all partial decryption zkps
  std::vector<PartialDecryptionRow> pd_rows = this->db_driver->all_partial_decryptions();
  std::vector<PartialDecryptionRow> valid_pd_rows;
  for (int i = 0; i < pd_rows.size(); i++){
    PartialDecryptionRow pd_row = pd_rows[i];
    ArbiterToWorld_PartialDecryption_Message a2w_pd_m;
    a2w_pd_m.arbiter_id = pd_row.arbiter_id;
    a2w_pd_m.arbiter_vk_path = pd_row.arbiter_vk_path;
    a2w_pd_m.dec = pd_row.dec;
    a2w_pd_m.zkp = pd_row.zkp;
    Integer key;
    LoadInteger(a2w_pd_m.arbiter_vk_path, key);
    if (!ElectionClient::VerifyPartialDecryptZKP(a2w_pd_m, key)){continue;}
    valid_pd_rows.push_back(pd_row);
  }
  std::cout << "Election successful" << std::endl;
  // 3. combines the partial decryptions to recieve the final result
  std::vector<Integer> final_result = ElectionClient::CombineResults(one_vote, valid_pd_rows);
  // 4. return votes
  std::cout << "Election successful" << std::endl;
  for (int i = 0; i < CANDIDATE_NUMBER; i++){
    std::cout << final_result[i] << std::endl;
  }
  return std::pair<std::vector<Integer>, bool>(final_result, true);
}
