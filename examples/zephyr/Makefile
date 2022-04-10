CWD = $(realpath $(CURDIR))
ZEPHYR_DIR ?= $(realpath ../../../zephyrproject)
BOARD ?= nucleo_f746zg
EXAMPLE ?= websocket-server

example:
	true

build:
	cp ../../mongoose.c ../../mongoose.h $(EXAMPLE)/src/
	cd $(ZEPHYR_DIR) && west build -b $(BOARD) -p auto $(CWD)/$(EXAMPLE)

flash:
	cd $(ZEPHYR_DIR) && west flash

clean:
	rm -rf */*/mongoose.*
