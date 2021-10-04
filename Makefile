BUILD ?= build

default: all

CFLAGS := -Wall -Wextra -g3 -fvisibility=default -fPIC -I.

LDFLAGS := -L$(BUILD) -L/usr/lib -lssl -lcrypto -lcurl -ljson-c

PREFIX ?= /usr

all: $(BUILD)/libzcure_client.so $(BUILD)/zcure_client_example $(BUILD)/zcure_server $(BUILD)/libzcure_server.so $(BUILD)/zcure_server_example $(BUILD)/ip_logger_client $(BUILD)/ip_logger_server $(BUILD)/zcure.service $(BUILD)/ip_logger.service

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	gcc -MMD -c $< $(CFLAGS) -o $@

$(BUILD)/libzcure_client.so: $(BUILD)/lib/client/client.o $(BUILD)/common/common.o
	gcc -shared -o $@ $^ -lssl -lcrypto

$(BUILD)/zcure_client_example: LDFLAGS += -lzcure_client
$(BUILD)/zcure_client_example: $(BUILD)/bin/client_example/main.o $(BUILD)/libzcure_client.so
	gcc $< -o $@ $(LDFLAGS)

$(BUILD)/zcure_server: $(BUILD)/bin/server/main.o $(BUILD)/common/common.o
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/libzcure_server.so: $(BUILD)/lib/server/server.o $(BUILD)/common/common.o
	gcc -shared -o $@ $^ -lssl -lcrypto

$(BUILD)/zcure_server_example: LDFLAGS += -lzcure_server
$(BUILD)/zcure_server_example: $(BUILD)/bin/server_example/main.o $(BUILD)/libzcure_server.so
	gcc $< -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/ip_logger_client: LDFLAGS += -lzcure_client
$(BUILD)/ip_logger_client: $(BUILD)/bin/ip_logger/client_app.o $(BUILD)/libzcure_client.so
	gcc $< -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/ip_logger_server: LDFLAGS += -lzcure_server
$(BUILD)/ip_logger_server: $(BUILD)/bin/ip_logger/server_app.o $(BUILD)/libzcure_server.so
	gcc $< -o $@ $(CFLAGS) $(LDFLAGS)

$(BUILD)/zcure.service: service/zcure.service
	PREFIX=${PREFIX} envsubst < $^ > $@

$(BUILD)/ip_logger.service: service/ip_logger.service
	PREFIX=${PREFIX} envsubst < $^ > $@

install:
	mkdir -p $(PREFIX)/lib/
	mkdir -p $(PREFIX)/bin/
	install $(BUILD)/libzcure_client.so $(PREFIX)/lib/
	install $(BUILD)/libzcure_server.so $(PREFIX)/lib/
	install $(BUILD)/zcure_server $(PREFIX)/bin/
	install $(BUILD)/ip_logger_* $(PREFIX)/bin/
	install -m 644 $(BUILD)/zcure.service /etc/systemd/system/
	install -m 644 $(BUILD)/ip_logger.service /etc/systemd/system/

clean:
	rm -rf $(BUILD)/*

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

-include $(call rwildcard, $(BUILD), *.d)
