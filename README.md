### How to build?

```
g++ main.cpp -L"path" -I"path" -lssl -lcurl -lcrypto -o main -std=c++11
```

example!

```
g++ main.cpp -L/opt/homebrew/opt/openssl@3/lib -I/opt/homebrew/opt/openssl@3/include -lssl -lcurl -lcrypto -o main -std=c++11
```
