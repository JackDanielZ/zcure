BUILD ?= build

default: all

CFLAGS := -Wall -Wextra -g3 -fvisibility=default -fPIC -I.

LDFLAGS := -L$(BUILD) -lssl -lcrypto -lcurl

all: $(BUILD)/libzcure_client.so $(BUILD)/zcure_client_example $(BUILD)/zcure_server $(BUILD)/libzcure_server.so $(BUILD)/zcure_server_example

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	gcc -c $^ $(CFLAGS) -o $@

$(BUILD)/libzcure_client.so: $(BUILD)/lib/client/client.o $(BUILD)/common/common.o
	gcc -shared -o $@ $^ -lssl -lcrypto

$(BUILD)/zcure_client_example: LDFLAGS += -lzcure_client
$(BUILD)/zcure_client_example: $(BUILD)/bin/client_example/main.o $(BUILD)/libzcure_client.so
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/zcure_server: $(BUILD)/bin/server/main.o $(BUILD)/common/common.o
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/libzcure_server.so: $(BUILD)/lib/server/server.o $(BUILD)/common/common.o
	gcc -shared -o $@ $^ -lssl -lcrypto

$(BUILD)/zcure_server_example: LDFLAGS += -lzcure_server
$(BUILD)/zcure_server_example: $(BUILD)/bin/server_example/main.o $(BUILD)/libzcure_server.so
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(BUILD)/*
