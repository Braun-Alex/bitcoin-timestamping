// Copyright (c) 2009-2022 Braun-Alex
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <rpc/util.h>
#include <util/message.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <crypto/sha3.h>
#include <wallet/coincontrol.h>

#include <univalue.h>
#include <filesystem>
#include <fstream>
#include <random>

namespace wallet {
    RPCHelpMan timestampdata()
    {
        return RPCHelpMan{"timestampdata",
                          "\nTimestamp data using SHA3-256 and transaction signature randomizer" +
                          HELP_REQUIRING_PASSPHRASE,
                          {
                                  {"filepath", RPCArg::Type::STR, RPCArg::Optional::NO, "The file to the path to use for timestamping."},
                          },
                          RPCResult{
                                  RPCResult::Type::STR_HEX, "txid", "The timestamping transaction id."
                          },
                          RPCExamples{
                                  "\nUnlock the wallet for 300 seconds\n"
                                  + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 300") +
                                  "\nTimestamp a PDF document\n"
                                  + HelpExampleCli("timestampdata", "\"/home/user/document.pdf\"") +
                                  "\nTimestamp a PNG image\n"
                                  + HelpExampleCli("timestampdata", "\"/home/user/image.png\"") +
                                  "\nAs a JSON-RPC call\n"
                                  + HelpExampleRpc("timestampdata", "\"/home/user/document.pdf\"")
                          },
                          [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
                          {
                              const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
                              if (!pwallet) return UniValue::VNULL;

                              LOCK(pwallet->cs_wallet);

                              EnsureWalletIsUnlocked(*pwallet);

                              const double MIN_LIMIT = 0.00000001, MAX_LIMIT = 0.000001;

                              std::string strFilePath = request.params[0].get_str();

                              if (!std::filesystem::exists(strFilePath)) {
                                  throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid filepath");
                              }

                              if (!std::filesystem::is_regular_file(strFilePath)) {
                                  throw JSONRPCError(RPC_INVALID_PARAMETER, "File is not regular");
                              }

                              std::ifstream file(strFilePath);
                              std::ostringstream data;
                              if (file) {
                                  while (file) {
                                      data << file.get();
                                  }
                              }

                              auto bytes = ParseHex(data.str());
                              SHA3_256 shaInstance;
                              unsigned char hash[SHA3_256::OUTPUT_SIZE];
                              shaInstance.Write(bytes).Finalize(hash);
                              std::string dataHash = HexStr(hash);

                              mapValue_t mapValue;
                              bool fSubtractFeeFromAmount = false;
                              CCoinControl coin_control;

                              std::optional<OutputType> parsed = ParseOutputType("bech32m");
                              const OutputType output_type = parsed.value();
                              if (!pwallet->CanGetAddresses()) {
                                  throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
                              }
                              const std::string label;
                              auto op_dest = pwallet->GetNewDestination(output_type, label);

                              if (!op_dest) {
                                  throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
                              }

                              std::random_device rd;
                              std::mt19937 generator(rd());
                              std::uniform_real_distribution<> distribution(MIN_LIMIT, MAX_LIMIT);

                              std::string newAddress = EncodeDestination(*op_dest);
                              UniValue address_amounts(UniValue::VOBJ);
                              address_amounts.pushKV(newAddress, distribution(generator));
                              UniValue subtractFeeFromAmount(UniValue::VARR);
                              if (fSubtractFeeFromAmount) {
                                  subtractFeeFromAmount.push_back(newAddress);
                              }

                              std::vector<CRecipient> recipients;
                              ParseRecipients(address_amounts, subtractFeeFromAmount, recipients);
                              const bool verbose{request.params[10].isNull() ? false : request.params[10].get_bool()};

                              return SendMoney(*pwallet, coin_control, recipients, mapValue, verbose);
                          },
        };
    }
}