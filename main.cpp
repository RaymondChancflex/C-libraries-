#include <iostream>
#include <string>
#include <cstdlib>
#include <cpprest/asyncrt_utils.h>
#include <cpprest/json.h>
#include <cpprest/ws_client.h>
#include <openssl/sha.h>
#include <gmp.h>

#define NO_GMP_INCLUDE
extern "C"
{
#include "ecp.h"
}
#undef NO_GMP_INCLUDE

using namespace std;
using namespace web;
using namespace web::websockets::client;

#ifdef _WIN32
#define TO_JSON(x) utility::conversions::utf8_to_utf16(x)
#define TO_MESSAGE(x) utility::conversions::utf16_to_utf8(x)
#else
#define TO_JSON(x) x
#define TO_MESSAGE(x) x
#endif


int main(int argc, char** argv)
{
    srand(time(0));
    websocket_client client;
    client.connect(U("wss://api.coinflex.com/v1")).then([&]() {
        /* We've finished connecting. */
        websocket_outgoing_message msg;
        msg.set_utf8_message("I am a UTF-8 string! (Or close enough...)");
        // client.send(msg).then([](){ /* Successfully sent the message. */ });

        client.receive().then([](websocket_incoming_message msg) {
            return msg.extract_string();
            }).then([&](std::string body) {
                json::value v1 = json::value::parse(TO_JSON(body));
                utility::string_t server_nonce = v1.at(U("nonce")).as_string();
                vector<unsigned char> server_nonce_array = utility::conversions::from_base64(server_nonce);
                vector<unsigned char> client_nonce_array;
                client_nonce_array.resize(16);
                for (int i = 0; i < 16; i++)
                {
                    client_nonce_array[i] = rand() % 256;
                }
                utility::string_t client_nonce = utility::conversions::to_base64(client_nonce_array);
                uint64_t id = 405;
                utility::string_t paraphrase = U("Cct282828");
                utility::string_t cookie = U("jfLz5wApN/QLeFiKx6jDaId4iHA=");

                unsigned char message[40];
                for (int i = 0; i < 8; i++)
                {
                    message[i] = *((char*)(&id) + (7 - i));
                }
                for (int i = 0; i < 16; i++)
                {
                    message[i + 8] = server_nonce_array[i];
                }
                for (int i = 0; i < 16; i++)
                {
                    message[i + 24] = client_nonce_array[i];
                }

                unsigned char digest[28];
                SHA224((unsigned char*)message, 40, (unsigned char*)digest);

                unsigned char* seedPreHash = new unsigned char[paraphrase.size() + 8];
                for (int i = 0; i < 8; i++)
                {
                    seedPreHash[i] = *((char*)(&id) + (7 - i));
                }
                for (size_t i = 0; i < paraphrase.size(); i++)
                {
                    seedPreHash[i + 8] = (char)paraphrase[i];
                }

                unsigned char seed_array[28];
                SHA224((unsigned char*)seedPreHash, paraphrase.size() + 8, (unsigned char*)seed_array);
                delete[] seedPreHash;

                // d is key
                // z is digest

                mp_limb_t r[MP_NLIMBS(29)], s[MP_NLIMBS(29)], d[MP_NLIMBS(29)], z[MP_NLIMBS(29)];
                uint8_t rb[28], sb[28], db[28], zb[28];

                for (int i = 0; i < 28; i++)
                {
                    db[i] = (uint8_t)seed_array[i];
                    zb[i] = (uint8_t)digest[i];
                }

#if GMP_LIMB_BITS == 32
                z[sizeof * z / sizeof z - 1] = d[sizeof * d / sizeof d - 1] = 0;
#endif
                bytes_to_mpn(d, db, sizeof db);
                bytes_to_mpn(z, zb, sizeof zb);
                ecp_sign(r, s, secp224k1_p, secp224k1_a, *secp224k1_G, secp224k1_n, d, z, MP_NLIMBS(29));
                mpn_to_bytes(rb, r, sizeof rb);
                mpn_to_bytes(sb, s, sizeof sb);

                vector<unsigned char> rv;
                vector<unsigned char> sv;
                rv.resize(28);
                sv.resize(28);
                for (int i = 0; i < 28; i++)
                {
                    rv[i] = (unsigned char)rb[i];
                    sv[i] = (unsigned char)sb[i];
                }
                utility::string_t r64 = utility::conversions::to_base64(rv);
                utility::string_t s64 = utility::conversions::to_base64(sv);

                json::value authenticationRequestMessage = json::value::object();
                authenticationRequestMessage[U("method")] = json::value::string(U("Authenticate"));
                authenticationRequestMessage[U("user_id")] = json::value(id);
                authenticationRequestMessage[U("cookie")] = json::value::string(cookie);
                authenticationRequestMessage[U("nonce")] = json::value::string(client_nonce);
                authenticationRequestMessage[U("signature")] = json::value::array();
                authenticationRequestMessage[U("signature")][0] = json::value::string(r64);
                authenticationRequestMessage[U("signature")][1] = json::value::string(s64);

                utility::stringstream_t authenticationRequestMessageStream;
                authenticationRequestMessage.serialize(authenticationRequestMessageStream);
                websocket_outgoing_message authenticationRequestOutgoingMessage;
                authenticationRequestOutgoingMessage.set_utf8_message(TO_MESSAGE(authenticationRequestMessageStream.str()));
                client.send(authenticationRequestOutgoingMessage).then([&]() {
                    client.receive().then([](websocket_incoming_message msg) {
                        return msg.extract_string();
                        }).then([&](std::string authenticationResponse) {

                            cout << authenticationResponse << endl;

                            json::value getBalanceRequestMessage = json::value::object();
                            getBalanceRequestMessage[U("method")] = json::value::string(U("GetBalances"));
                            utility::stringstream_t getBalanceRequestMessageStream;
                            getBalanceRequestMessage.serialize(getBalanceRequestMessageStream);
                            websocket_outgoing_message getBalanceRequestOutgoingMessage;
                            getBalanceRequestOutgoingMessage.set_utf8_message(TO_MESSAGE(getBalanceRequestMessageStream.str()));
                            client.send(getBalanceRequestOutgoingMessage).then([&]() {
                                client.receive().then([](websocket_incoming_message msg) {
                                    return msg.extract_string();
                                    }).then([&](std::string getBalanceResponse) {
                                        cout << getBalanceResponse << endl;
                                        wcout << U("Press any key to continue") << endl;
                                        });
                                });
                            });
                    });
                });

        });
    string s;
    cin >> s;
}
