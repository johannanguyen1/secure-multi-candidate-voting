#include "../include-shared/keyloaders.hpp"
#include "../include-shared/constants.hpp"
#include "../include-shared/util.hpp"

/**
 * Save the RSA key at the file.
 */
void SaveRSAPrivateKey(const std::string &filename,
                       const CryptoPP::PrivateKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Load the RSA key from the file.
 */
void LoadRSAPrivateKey(const std::string &filename, CryptoPP::PrivateKey &key) {
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("RSA private key loading failed");
  }
}

/**
 * Save the RSA key at the file.
 */
void SaveRSAPublicKey(const std::string &filename,
                      const CryptoPP::PublicKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Save the vote struct at the file.
 */
void SaveVote(const std::string &filename, Vote_Ciphertext &vote) {
  std::vector<unsigned char> vote_serialized;
  vote.serialize(vote_serialized);

  std::string vote_str = chvec2str(vote_serialized);
  CryptoPP::StringSource(vote_str, true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load the vote struct from the file.
 */
void LoadVote(const std::string &filename, Vote_Ciphertext &vote) {
  std::string vote_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(vote_str));
  std::vector<unsigned char> vote_serialized = str2chvec(vote_str);
  vote.deserialize(vote_serialized);
}

/** 
 * Save vote wrapper to file.
*/
void SaveVoteWrapper(const std::string &filename, Vote_Ciphertext_Wrapper &vote_wrapper) {
  std::vector<unsigned char> vote_wrapper_serialized;
  vote_wrapper.serialize(vote_wrapper_serialized);

  std::string vote_str = chvec2str(vote_wrapper_serialized);
  CryptoPP::StringSource(vote_str, true,
                         new CryptoPP::FileSink(filename.c_str()));
}
/**
 * Load the vote wrapper from the file.
 */
void LoadVoteWrapper(const std::string &filename, Vote_Ciphertext_Wrapper &vote_wrapper) {
  std::string vote_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(vote_str));
  std::vector<unsigned char> vote_serialized = str2chvec(vote_str);
  vote_wrapper.deserialize(vote_serialized);
}

/**
 * Save the vote ZKP struct at the file.
 */
void SaveVoteZKP(const std::string &filename, VoteZKP_Struct &vote_zkp) {
  std::vector<unsigned char> vote_zkp_serialized;
  vote_zkp.serialize(vote_zkp_serialized);
  std::string vote_zkp_str = chvec2str(vote_zkp_serialized);
  CryptoPP::StringSource(vote_zkp_str, true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load the vote ZKP struct from the file.
 */
void LoadVoteZKP(const std::string &filename, VoteZKP_Struct &vote_zkp) {
  std::string vote_zkp_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(vote_zkp_str));
  std::vector<unsigned char> vote_zkp_serialized = str2chvec(vote_zkp_str);
  vote_zkp.deserialize(vote_zkp_serialized);
}

/** 
 * Save zkp wrapper to file.
*/
void SaveZKPWrapper(const std::string &filename, VoteZKP_Wrapper &zkp_wrapper) {
  std::vector<unsigned char> zkp_wrapper_serialized;
  zkp_wrapper.serialize(zkp_wrapper_serialized);

  std::string zkp_str = chvec2str(zkp_wrapper_serialized);
  CryptoPP::StringSource(zkp_str, true,
                         new CryptoPP::FileSink(filename.c_str()));
}
/**
 * Load the vote wrapper from the file.
 */
void LoadZKPWrapper(const std::string &filename, VoteZKP_Wrapper &zkp_wrapper) {
  std::string zkp_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(zkp_str));
  std::vector<unsigned char> zkp_serialized = str2chvec(zkp_str);
  zkp_wrapper.deserialize(zkp_serialized);
}

/**
 * Load the RSA key from the file.
 */
void LoadRSAPublicKey(const std::string &filename, CryptoPP::PublicKey &key) {
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("RSA public key loading failed");
  }
}

/**
 * Save an integer at the file.
 */
void SaveInteger(const std::string &filename, const CryptoPP::Integer &i) {
  CryptoPP::StringSource(CryptoPP::IntToString(i), true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load an integer from the file.
 */
void LoadInteger(const std::string &filename, CryptoPP::Integer &i) {
  std::string i_str;
  CryptoPP::FileSource(filename.c_str(), true, new CryptoPP::StringSink(i_str));
  i = CryptoPP::Integer(i_str.c_str());
}

/**
 * Loads the election public key from the files provided.
 */
void LoadElectionPublicKey(const std::vector<std::string> &filenames,
                           CryptoPP::Integer &public_key) {
  CryptoPP::Integer final_key = CryptoPP::Integer::One();
  for (auto path : filenames) {
    CryptoPP::Integer key;
    LoadInteger(path, key);
    final_key *= key;
  }
  public_key = CryptoPP::Integer(final_key);
}
