CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LDFLAGS = -lpthread

SRC = main.cpp util.cpp config.cpp collector.cpp alerts.cpp http_server.cpp dashboard.cpp
OUT = clawguard

.PHONY: all clean install

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OUT)

install: $(OUT)
	install -m 755 $(OUT) /usr/local/bin/clawguard
	@echo "✓ Installed to /usr/local/bin/clawguard"
