#include <cryptmt.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

using namespace std;
using namespace cryptmt;

typedef struct OPTIONS_T {
    bool encrypt;
    bool verbose;
    int keysize;
    string inputfile;
    string outputfile;
    string keyfile;
    string key;
} options_t;

static uint64_t byte_count = 0;
static double encrypt_time = 0;
static double read_time = 0;
static double write_time = 0;

static void
output_help(string& pgm);
static bool
parse_opt(options_t& opt, int argc, char **argv);
static bool
file_check(string& filename, bool output);

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define _CRT_SECURE_NO_WARNINGS
bool
parse_opt(options_t& opt, int argc, char **argv)
{
    string pgm = argv[0];
    int pos = 1;
    opt.encrypt = true;
    opt.keysize = 128;
    bool error = false;
    opt.verbose = false;
    while (pos < argc) {
        if (argv[pos][0] != '-') {
            pos++;
            continue;
        }
        switch (argv[pos][1]) {
        case 'v':
            opt.verbose = true;
            pos++;
            break;
        case 'e':
            opt.encrypt = true;
            pos++;
            break;
        case 'd':
            opt.encrypt = false;
            pos++;
            break;
        case 'i':
            pos++;
            opt.inputfile = argv[pos];
            pos++;
            break;
        case 'o':
            pos++;
            opt.outputfile = argv[pos];
            pos++;
            break;
        case 'k':
            pos++;
            opt.key = argv[pos];
            pos++;
            break;
        case 'f':
            pos++;
            opt.keyfile = argv[pos];
            pos++;
            break;
        case 's':
            errno = 0;
            if (argv[pos][2]!= '\0') {
                opt.keysize = strtol(&argv[pos][2], NULL, 10);
            } else {
                pos++;
                opt.keysize = strtol(argv[pos], NULL, 10);
            }
            if (errno) {
                error = true;
                cerr << "keysize must be a number" << endl;
            }
            if ((opt.keysize / 128 == 0)
                || (opt.keysize / 128 > 16)
                || (opt.keysize % 128 != 0)) {
                error = true;
                cerr << "keysize error" << endl;
            }
            break;
        case '?':
        default:
            error = true;
            break;
        }
        if (error) {
            break;
        }
    }
    if (error) {
        output_help(pgm);
        return false;
    }
    if (!opt.inputfile.empty()) {
        if (!file_check(opt.inputfile, false)) {
            return false;
        }
    }
    if (!opt.outputfile.empty()) {
        if (!file_check(opt.outputfile, true)) {
            return false;
        }
    }
    if (opt.key.empty() && !opt.keyfile.empty()) {
        if (!file_check(opt.keyfile, false)) {
            return false;
        }
    }
    return true;
}
#else
#include <getopt.h>
/**
 * command line option parser
 * @param opt a structure to keep the result of parsing
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @return command line options have error, or not
 */
static bool
parse_opt(options_t& opt, int argc, char **argv)
{
    int c;
    bool error = false;
    string pgm = argv[0];
    static struct option longopts[] = {
        {"encrypt", no_argument, NULL, 'e'},
        {"decrypt", no_argument, NULL, 'd'},
        {"inputfile", required_argument, NULL, 'i'},
        {"outputfile", required_argument, NULL, 'o'},
        {"key", required_argument, NULL, 'k'},
        {"keyfile", required_argument, NULL, 'f'},
        {"keysize", required_argument, NULL, 's'},
        {"verbose", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}};
    opt.encrypt = true;
    opt.keysize = 128;
    opt.verbose = false;
    errno = 0;
    for (;;) {
        c = getopt_long(argc, argv, "edvi:o:k:f:s:", longopts, NULL);
        if (error) {
            break;
        }
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'e':
            opt.encrypt = true;
            break;
        case 'd':
            opt.encrypt = false;
            break;
        case 'v':
            opt.verbose = true;
            break;
        case 'i':
            opt.inputfile = optarg;
            break;
        case 'o':
            opt.outputfile = optarg;
            break;
        case 'k':
            opt.key = optarg;
            break;
        case 'f':
            opt.keyfile = optarg;
            break;
        case 's':
            opt.keysize = strtol(optarg, NULL, 10);
            if (errno) {
                error = true;
                cerr << "keysize must be a number" << endl;
            }
            if ((opt.keysize / 128 == 0)
                || (opt.keysize / 128 > 16)
                || (opt.keysize % 128 != 0)) {
                error = true;
                cerr << "keysize error" << endl;
            }
            break;
        case '?':
        default:
            error = true;
            break;
        }
        if (error) {
            break;
        }
    }
    if (error) {
        output_help(pgm);
        return false;
    }
    if (!opt.inputfile.empty()) {
        if (!file_check(opt.inputfile, false)) {
            return false;
        }
    }
    if (!opt.outputfile.empty()) {
        if (!file_check(opt.outputfile, true)) {
            return false;
        }
    }
    if (opt.key.empty() && !opt.keyfile.empty()) {
        if (!file_check(opt.keyfile, false)) {
            return false;
        }
    }
    return true;
}
#endif

static bool
file_check(string& filename, bool output)
{
    if (output) {
        ofstream ofs(filename.c_str());
        if (ofs) {
            ofs.close();
            return true;
        } else {
            cerr << "can't open file:" << filename << endl;
            return false;
        }
    } else {
        ifstream ifs(filename.c_str());
        if (ifs) {
            ifs.close();
            return true;
        } else {
            cerr << "can't open file:" << filename << endl;
            return false;
        }
    }
}

/**
 * showing help message
 * @param pgm program name
 */
static void
output_help(string& pgm)
{
    cerr << "usage:" << endl;
    cerr << pgm
         << " [--encrypt|--decrypt] [--inputfile ifile] [--outputfile ofile] "
         << "[--key key] [--keyfile kfile]"
         << "[--keysize size]  [--verbose]" << endl;
#if defined(_MSC_VER) || defined(__BORLANDC__)
    static string help_string = "\n"
        "-e           Encryption.\n"
        "-d           Decryption.\n"
        "             If omitted encryption is assumed. But encryption \n"
        "             and decryption are just the same.\n"
        "-i ifile     Input file. If omitted, standard input is used.\n"
        "-o ofile     Output file. If omitted, standard output is used.\n"
        "-k key       Key for encryption/decryption.\n"
        "-f kfile     File which contains encryption/decryption key.\n"
        "             If both of --key and --keyfile are omitted, user \n"
        "             will be prompted to input the key.\n"
        "             If both of --key and --keyfile are specified, --key\n"
        "             will be used.\n"
        "-s size      Size of key. Size should be multiple of 128 and less\n"
        "             than or equals to 2048. If omitted 128 is used.\n"
        "-v           Show detailed message\n";
#else //defined(_MSC_VER) || defined(__BORLANDC__)
    static string help_string = "\n"
        "--encrypt, -e           Encryption.\n"
        "--decrypt, -d           Decryption.\n"
        "                        If omitted encryption is assumed. But encryption \n"
        "                        and decryption are just the same.\n"
        "--inputfile, -i ifile   Input file. If omitted, standard input is used.\n"
        "--outputfile, -o ofile  Output file. If omitted, standard output is used.\n"
        "--key, -k key           Key for encryption/decryption.\n"
        "--keyfile, -f kfile     File which contains encryption/decryption key.\n"
        "                        If both of --key and --keyfile are omitted, user \n"
        "                        will be prompted to input the key.\n"
        "                        If both of --key and --keyfile are specified, --key\n"
        "                        will be used.\n"
        "--keysize, -s size      Size of key. Size should be multiple of 128 and less\n"
        "                        than or equals to 2048. If omitted 128 is used.\n"
        "--verbose, -v           Show detailed message\n";
#endif //defined(_MSC_VER) || defined(__BORLANDC__)
    cerr << help_string << endl;
}

void
read_key(uint8_t *key, const string& keyfile, int keysize)
{
    ifstream ifs(keyfile.c_str());
    if (ifs) {
        ifs.read(reinterpret_cast<char *>(key), keysize / 8);
    } else {
        cerr << "error in reading keyfile" << endl;
    }
}

void
read_key(uint8_t *key, int keysize)
{
    string buff;
    cout << "Input encryption key:" << endl;
    getline(cin, buff);
    if (buff.length() < static_cast<unsigned int>(keysize) / 8) {
        strcpy(reinterpret_cast<char *>(key), buff.c_str());
    } else {
        strncpy(reinterpret_cast<char *>(key), buff.c_str(), keysize/ 8);
    }
#if defined(DEBUG)
    cout << "key = |" << buff << "|" << endl;
#endif
}

void
encrypt(CryptMT& cmt, istream& is, ostream& os)
{
    clock_t start;
    int mag = 100;
    size_t buffer_size = cmt.blockLength() * mag;
    uint8_t *input = reinterpret_cast<uint8_t *>(aligned_alloc(buffer_size));
    uint8_t *output = reinterpret_cast<uint8_t *>(aligned_alloc(buffer_size));
    while (is && os) {
        start = clock();
        is.read(reinterpret_cast<char *>(input), buffer_size);
        read_time += static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
        streamsize count = is.gcount();
        byte_count += count;
        if (count == 0) {
            break;
        } else if ((size_t)count == buffer_size) {
            start = clock();
            cmt.encryptBlocks(input, output, mag);
            encrypt_time += static_cast<double>(clock() - start)
                / CLOCKS_PER_SEC;
            start = clock();
            os.write(reinterpret_cast<char *>(output), buffer_size);
            write_time += static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
        } else {
            start = clock();
            cmt.encrypt(input, output, count);
            encrypt_time += static_cast<double>(clock() - start)
                / CLOCKS_PER_SEC;
            start = clock();
            os.write(reinterpret_cast<char *>(output), count);
            write_time += static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
            break;
        }
    }
    aligned_free(input);
    aligned_free(output);
}

int
main (int argc, char *argv[])
{
    options_t opt;
    if (!parse_opt(opt, argc, argv)) {
        return -1;
    }
    uint8_t *key = new uint8_t[opt.keysize / 8 + 1];
    memset(key, 0, opt.keysize / 8 + 1);
    if (opt.key.empty() && !opt.keyfile.empty()) {
        read_key(key, opt.keyfile, opt.keysize);
    } else if (opt.key.empty()) {
        read_key(key, opt.keysize);
    } else {
        strncpy(reinterpret_cast<char *>(key),
                opt.key.c_str(), opt.keysize / 8);
    }
    CryptMT cmt(key, opt.keysize, opt.keysize);
    uint8_t * iv = new uint8_t[opt.keysize / 8];
    strncpy(reinterpret_cast<char *>(iv),
            reinterpret_cast<char *>(key),
            opt.keysize / 8);
#if defined(DEBUG)
    cout << "key:";
    for (int i = 0; i < opt.keysize / 8; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(key[i]);
    }
    cout << endl;
    cout << " iv:";
    for (int i = 0; i < opt.keysize / 8; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(iv[i]);
    }
    cout << endl;
#endif
    cmt.IVSetUp(iv);
    delete[] key;
    delete[] iv;

    istream *is;
    ifstream ifs;
    if (opt.inputfile.empty()) {
        is = &cin;
    } else {
        ifs.open(opt.inputfile.c_str(), ios::binary);
        is = &ifs;
    }
    ostream *os;
    ofstream ofs;
    if (opt.outputfile.empty()) {
        os = &cout;
    } else {
        ofs.open(opt.outputfile.c_str(), ios::binary);
        os = &ofs;
    }
    encrypt(cmt, *is, *os);
    if (opt.verbose) {
        double size = byte_count;
        const char suffix_char[] = {'K','M','G','T'};
        string suffix = "";
        for (int i = 0; i < 3; i++) {
            if (size > 1000) {
                size = size / 1000;
                suffix = suffix_char[i+1];
            } else {
                break;
            }
        }
        cerr << "   file size: " << dec << size << suffix << endl;
        cerr << "encrypt time: " << dec << encrypt_time * 1000 << "ms" << endl;
        cerr << "   read_time: "  << dec << read_time * 1000 << "ms" << endl;
        cerr << "  write_time: " << dec << write_time * 1000 << "ms" << endl;
    }
    ifs.close();
    ofs.close();
    return 0;
}
