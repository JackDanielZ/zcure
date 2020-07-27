PREFIX = /opt/mine

BUILD ?= build

default: all

CFLAGS := -Wall -Wextra -g3 -fvisibility=default -fPIC -I.

LDFLAGS := -L$(BUILD) -lzcure -lssl -lcrypto

all: $(BUILD)/libzcure.so $(BUILD)/zcure $(BUILD)/zcure_server

$(BUILD)/libzcure.so: $(BUILD)/zcure_client.o
	gcc -shared -o $@ $^ -lssl -lcrypto

$(BUILD)/zcure_client.o: zcure_client.c
	@mkdir -p $(@D)
	gcc -c $^ $(CFLAGS) -o $@

$(BUILD)/zcure: zcure_example.c $(BUILD)/libzcure.so
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/zcure_server: zcure_server.c $(BUILD)/libzcure.so
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(BUILD)/*.o $(BUILD)/*.so $(BUILD)/zcure
