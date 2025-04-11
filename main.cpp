#include <iostream>
#include <unordered_map>
#include <vector>
#include <curl/curl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include "json.hpp"
#include "response_types.hpp"
#include "whitelist.hpp"

using json = nlohmann::json;

using namespace std;

namespace ns {
    struct Source {
        ResponseType type;
        string src;
        JsonResponseProcessor json_response_processor;
    };
}

static size_t WriteCallback(void *contents, const size_t size, size_t nmemb, void *userp) {
    static_cast<string *>(userp)->append(static_cast<char *>(contents), size * nmemb);
    return size * nmemb;
}

string fetch(const string& src)
{
    string readBuffer;

    if (CURL *curl = curl_easy_init()) {
        curl_easy_setopt(curl, CURLOPT_URL, src.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

vector<string> split(const string &target, const string &delimiter) {
    vector<string> result;
    size_t start = 0;
    size_t end = target.find(delimiter);

    while (end != string::npos) {
        result.push_back(target.substr(start, end - start));
        start = end + delimiter.length();
        end = target.find(delimiter, start);
    }

    result.push_back(target.substr(start));
    return result;
}

template <typename T>
string join(const T& v, const string& delim) {
    ostringstream s;
    for (const auto& i : v) {
        if (&i != &v[0]) {
            s << delim;
        }
        s << i;
    }
    return s.str();
}

void add_to_domains(const vector<string>& items, unordered_map<string, string> &domains)
{
    for (auto & i : items) {
        try {
            // checks if domain exists in unordered_map, if not, it will throw
            domains.at(i);

        }
        catch(const exception& e) {
            // doesn't exist on map, insert it
            domains.insert( {{ i, i }} );
        }
    }
}

bool is_whitelisted(const string& domain)
{
    return find(whitelist.begin(), whitelist.end(), domain) != whitelist.end();
}

vector<string> process_response(const string& response, const ns::Source& source)
{
    vector<string> domains;
    if (source.type == ResponseType::List) {
        vector<string> v = split(response, "\n");
        for (int i = v.size() - 1; i >= 0; i--) {
            if (v[i].rfind('#', 0) == 0 || v[i].empty() || is_whitelisted(v[i])) {
                v.erase(v.begin() + i);
            }
        }
        domains = v;
    }
    if (source.type == ResponseType::Json) {
        json j = json::parse(response);
        if (source.json_response_processor == JsonResponseProcessor::Inboxes) {
            for (const auto& d : j.at("domains")) {
                if (!is_whitelisted(d.at("qdn"))) {
                    domains.push_back(d.at("qdn"));
                }
            }
        }
        if (source.json_response_processor == JsonResponseProcessor::TempMailIo) {
            for (const auto& d : j.at("domains")) {
                if (!is_whitelisted(d)) {
                    domains.push_back(d);
                }
            }
        }
    }
    return domains;
}

int main(int argc, char* argv[])
{
    // handling of command line flags
    string output_type = "txt";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                cout << "\033[1;31mERROR:\033[0m not enough arguments." << endl;
                return 0;
            }

            char* value = argv[i + 1];

            if (strcmp(value, "json") == 0 || strcmp(value, "txt") == 0) {
                output_type = value;
                i++;
            } else {
                cout << "\033[1;31mERROR\033[0m Invalid value for output: " + string(value)  << endl;
                cout << "  Possible values are: json or txt." << endl;
                cout << "  Default value: txt" << endl;
                return 0;
            }
        }
    } // end handling of command line flags

    const vector<ns::Source> sources = {
        {ResponseType::List, "https://gist.githubusercontent.com/adamloving/4401361/raw/"},
        {ResponseType::List, "https://gist.githubusercontent.com/jamesonev/7e188c35fd5ca754c970e3a1caf045ef/raw/"},
        {ResponseType::List, "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mail-data-hosts-net.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/manual.txt"},
        {ResponseType::List, "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf"},
        {ResponseType::List, "https://raw.githubusercontent.com/daisy1754/jp-disposable-emails/master/list.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/flotwig/disposable-email-addresses/master/domains.txt"},
        {ResponseType::List, "https://raw.githubusercontent.com/GeroldSetz/emailondeck.com-domains/refs/heads/master/emailondeck.com_domains_from_bdea.cc.txt"},

        {ResponseType::Json, "https://inboxes.com/api/v2/domain", JsonResponseProcessor::Inboxes},
        {ResponseType::Json, "https://api.internal.temp-mail.io/api/v2/domains", JsonResponseProcessor::TempMailIo}
    };

    unordered_map<string, string> domains = {};

    for (const auto& source : sources) {
        string response = fetch(source.src);
        vector<string> items = process_response(response, source);
        add_to_domains(items, domains);
    }

    // get all keys from domains unordered_map
    vector<string> keys;
    keys.reserve(domains.size());
    for (const auto&[fst, snd] : domains) {
        keys.push_back(fst);
    }

    // create output file
    ofstream MyFile(output_type == "txt" ? "domains.txt" : "domains.json");

    if (MyFile.is_open()) {
        if (output_type == "txt") {
            string joined = join(keys, "\n");
            MyFile << joined;
        }
        
        if (output_type == "json") {
            json j = keys;
            MyFile << j.dump(2);
        }
        
        MyFile.close();
    } else {
        cout << "Unable to generate output file." << endl;
    }

    cout << "Domains added to domain." << output_type << ": " << domains.size() << endl;

    return 0;
}
