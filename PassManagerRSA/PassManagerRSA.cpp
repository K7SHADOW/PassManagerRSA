#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <openssl/bio.h>
#include <openssl/buffer.h>

using namespace std;
string base64Encode(const unsigned char* input, int length) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encoded;
}
vector<unsigned char> base64Decode(const string& input) {
    BIO* bio, * b64;
    int decodeLen = input.length();
    vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer.data(), decodeLen);
    BIO_free_all(bio);

    buffer.resize(length);
    return buffer;
}
void generateRSAKeys() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        cerr << "Key generation error!" << endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY_CTX_free(ctx);
    FILE* pubKeyFile;
    fopen_s(&pubKeyFile, "public.pem", "wb");
    if (!pubKeyFile) {
        cerr << "Error saving public key!" << endl;
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_PUBKEY(pubKeyFile, pkey);
    fclose(pubKeyFile);
    FILE* privKeyFile;
    fopen_s(&privKeyFile, "private.pem", "wb");
    if (!privKeyFile) {
        cerr << "Error saving private key!" << endl;
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_PrivateKey(privKeyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privKeyFile);

    cout << "Keys generated successfully!" << endl;
    EVP_PKEY_free(pkey);
}
string encryptRSA(const string& data) {
    FILE* pubKeyFile;
    fopen_s(&pubKeyFile, "public.pem", "rb");
    if (!pubKeyFile) {
        cerr << "Error reading public key!" << endl;
        return "";
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);

    if (!pkey) {
        cerr << "Error loading public key!" << endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        cerr << "Encryption error!" << endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)data.c_str(), data.size()) <= 0) {
        cerr << "Error determining encrypted data size!" << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    vector<unsigned char> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, (unsigned char*)data.c_str(), data.size()) <= 0) {
        cerr << "Encryption error!" << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // encrypt Base64
    return base64Encode(encrypted.data(), outlen);
}
string decryptRSA(const string& encryptedData) {
    // decrypt Base64
    vector<unsigned char> decodedData = base64Decode(encryptedData);

    FILE* privKeyFile;
    fopen_s(&privKeyFile, "private.pem", "rb");
    if (!privKeyFile) {
        cerr << "Error opening private key!" << endl;
        return "";
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);

    if (!pkey) {
        cerr << "Error loading private key!" << endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        cerr << "Decryption error!" << endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, decodedData.data(), decodedData.size()) <= 0) {
        cerr << "Error determining size of decrypted data!" << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    vector<unsigned char> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, decodedData.data(), decodedData.size()) <= 0) {
        cerr << "Decryption error!" << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return string(decrypted.begin(), decrypted.end());
}



string generatePassword(int length) {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    string password;

    for (int i = 0; i < length; ++i) {
        password += chars[rand() % chars.size()];
    }
    return password;
}


void savePassword(const string& service, const string& login, const string& password) {
    ofstream file("passwords.txt", ios::app);
    if (!file) {
        cerr << "Error opening file!" << endl;
        return;
    }

    string encryptedPassword = encryptRSA(password);
    if (encryptedPassword.empty()) {
        cerr << "Error while encrypting password!" << endl;
        return;
    }

    file << service << " " << login << " " << encryptedPassword << endl;
    file.close();
    cout << "Password saved!" << endl;
}

void findPassword(const string& service) {
    ifstream file("passwords.txt");
    if (!file) {
        cerr << "Error opening file!" << endl;
        return;
    }

    string serv, login, pass;
    bool found = false;

    while (file >> serv >> login >> pass) {
        if (serv == service) {
            string decryptedPassword = decryptRSA(pass);
            cout << "Service: " << serv << "\nLogin: " << login << "\nPassword: " << decryptedPassword << endl;
            found = true;
            break;
        }
    }
    file.close();

    if (!found) cout << "Password not found!" << endl;
}
int main() {
    srand(static_cast<unsigned int>(time(nullptr)));

    int choice;
    string service, login, password;

    while (true) {
        cout << "\nPassword manager:" << endl;
        cout << "1. Generate RSA keys" << endl;
        cout << "2. Save password" << endl;
        cout << "3. Find password" << endl;
        cout << "4. Generate password" << endl;
        cout << "5. Exit" << endl;
        cout << "Choice: ";
        cin >> choice;

        switch (choice) {
        case 1:
            generateRSAKeys();
            break;
        case 2:
            cout << "Enter service: ";
            cin >> service;
            cout << "Enter your login: ";
            cin >> login;
            cout << "Enter your password: ";
            cin >> password;
            savePassword(service, login, password);
            break;
        case 3:
            cout << "Enter service: ";
            cin >> service;
            findPassword(service);
            break;
        case 4:
            int length;
            cout << "Enter password length: ";
            cin >> length;
            cout << "Generated password: " << generatePassword(length) << endl;
            break;
        case 5:
            return 0;
        default:
            cout << "Wrong choice!" << endl;
        }
    }
}
