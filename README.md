# disposable-emails
A list of disposable/temporary email address domains.

Need to know if an email is a temporary email? This tool might help you out.
This program aggregates data from different sources and combines them into a single json file.
If a domain appears on the list, chances are it is a temporary/disposable email domain.

In case some of the sources turns into a bad actor and adds a non-temporary domain (i.e: `gmail.com` or `hotmail.com`), such domain can be whitelisted in the file `whitelist.hpp`.

## Dependencies
C++ 17 or greater

## Compiling
```sh
$ g++ main.cpp -o app -lcurl -std=c++17
```

## Running
```sh
$ ./app
```

## Flags
When running the program, flags can be passed in the command line
| Flag     | Short version | Possible values | Default |
| :------- | :------------ | :-------------- | :------ |
| --output | -o            | json, txt       | txt     |

```sh
$ ./app --output json
```